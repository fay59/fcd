//
// params_registry.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "anyarch_anycc.h"
#include "anyarch_interactive.h"
#include "call_conv.h"
#include "command_line.h"
#include "executable.h"
#include "metadata.h"
#include "params_registry.h"
#include "pass_executable.h"

#include <llvm/Analysis/PostDominators.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Module.h>

using namespace llvm;
using namespace std;

namespace
{
	class CallingConventionParser : public cl::generic_parser_base
	{
		struct OptionInfo : public GenericOptionInfo
		{
			cl::OptionValue<CallingConvention*> cc;
			
			OptionInfo(CallingConvention* cc)
			: GenericOptionInfo(cc->getName(), cc->getHelp()), cc(cc)
			{
			}
			
			OptionInfo(std::nullptr_t, std::nullptr_t)
			: GenericOptionInfo("auto", "autodetect"), cc(nullptr)
			{
			}
		};
		
		static vector<OptionInfo>& ccs()
		{
			static vector<OptionInfo> callingConventions;
			if (callingConventions.size() == 0)
			{
				for (CallingConvention* cc : CallingConvention::getCallingConventions())
				{
					callingConventions.emplace_back(cc);
				}
				
				sort(callingConventions.begin(), callingConventions.end(), [](OptionInfo& a, OptionInfo& b)
				{
					return a.Name < b.Name;
				});
				
				callingConventions.emplace(callingConventions.begin(), nullptr, nullptr);
			}
			return callingConventions;
		}
		
	public:
		typedef CallingConvention* parser_data_type;
		
		CallingConventionParser(cl::Option& o)
		: cl::generic_parser_base(o)
		{
		}
		
		virtual unsigned getNumOptions() const override
		{
			return static_cast<unsigned>(ccs().size());
		}
		
		virtual StringRef getOption(unsigned n) const override
		{
			return ccs().at(n).Name;
		}
		
		virtual StringRef getDescription(unsigned n) const override
		{
			return ccs().at(n).HelpStr;
		}
		
		virtual const cl::GenericOptionValue& getOptionValue(unsigned n) const override
		{
			return ccs().at(n).cc;
		}
		
		bool parse(cl::Option& o, StringRef argName, StringRef arg, CallingConvention*& value)
		{
			StringRef argVal = Owner.hasArgStr() ? arg : argName;
			for (const auto& info : ccs())
			{
				if (argVal == info.Name)
				{
					value = info.cc.getValue();
					return false;
				}
			}
			
			return o.error("Cannot find option named '" + argVal + "'!");
		}
	};
	
	cl::opt<CallingConvention*, false, CallingConventionParser> defaultCC("cc", cl::desc("Default calling convention"), cl::value_desc("name"), whitelist());
	
	template<unsigned N>
	bool findReg(const TargetRegisterInfo& reg, const SmallVector<ValueInformation, N>& from)
	{
		for (const auto& value : from)
		{
			if (value.type == ValueInformation::IntegerRegister && &reg == value.registerInfo)
			{
				return true;
			}
		}
		return false;
	}
	
	struct TemporaryTrue
	{
		bool old;
		bool& value;
		
		TemporaryTrue(bool& value)
		: value(value)
		{
			old = value;
			value = true;
		}
		
		~TemporaryTrue()
		{
			value = old;
		}
	};
}

ModRefInfo CallInformation::getRegisterModRef(const TargetRegisterInfo &reg) const
{
	// If it's a return value, then Mod;
	// if it's a parameter, then Ref;
	// otherwise, NoModRef, as far as the call information is concerned.
	// Two notable exceptions are the instruction pointer and the stack pointer, which have to be handled out of here.
	underlying_type_t<ModRefInfo> result = MRI_NoModRef;
	auto retBegin = return_begin();
	for (auto iter = begin(); iter != end(); ++iter)
	{
		if (iter->type == ValueInformation::IntegerRegister && &reg == iter->registerInfo)
		{
			result |= iter < retBegin ? MRI_Ref : MRI_Mod;
		}
	}
	
	return static_cast<ModRefInfo>(result);
}

ModRefInfo ParameterRegistryAAResults::getModRefInfo(ImmutableCallSite cs, const MemoryLocation &loc)
{
	if (auto func = cs.getCalledFunction())
	{
		auto iter = callInformation.find(func);
		if (iter != callInformation.end())
		if (const TargetRegisterInfo* info = targetInfo->registerInfo(*loc.Ptr))
		{
			return iter->second.getRegisterModRef(*info);
		}
	}
	
	return AAResultBase::getModRefInfo(cs, loc);
}

char ParameterRegistry::ID = 0;

ParameterRegistry::ParameterRegistry()
: ModulePass(ID)
{
}

ParameterRegistry::~ParameterRegistry()
{
}

CallInformation* ParameterRegistry::analyzeFunction(Function& fn)
{
	CallInformation& info = aaResults->callInformation[&fn];
	if (info.getStage() == CallInformation::New)
	{
		for (CallingConvention* cc : ccChain)
		{
			info.setStage(CallInformation::Analyzing);
			if (cc->analyzeFunction(*this, info, fn))
			{
				info.setCallingConvention(cc);
				info.setStage(CallInformation::Completed);
				break;
			}
			else
			{
				info.setStage(CallInformation::New);
				info.clear();
			}
		}
		
		if (info.getStage() != CallInformation::Completed)
		{
			info.setStage(CallInformation::Failed);
		}
	}
	
	return info.getStage() == CallInformation::Completed ? &info : nullptr;
}

void ParameterRegistry::setupCCChain()
{
	if (defaultCC != nullptr)
	{
		addCallingConvention(defaultCC);
	}
	else
	{
		if (Executable* executable = getExecutable())
		if (auto cc = CallingConvention::getMatchingCallingConvention(getTargetInfo(), *executable))
		{
			addCallingConvention(cc);
		}
	}
	
	if (ccChain.size() >= 1)
	{
		addCallingConvention(CallingConvention::getCallingConvention(CallingConvention_AnyArch_AnyCC::name));
		addCallingConvention(CallingConvention::getCallingConvention(CallingConvention_AnyArch_Interactive::name));
	}
	else
	{
		llvm_unreachable("no system calling convention was specified and none could be inferred");
	}
}

Executable* ParameterRegistry::getExecutable()
{
	return getAnalysis<ExecutableWrapper>().getExecutable();
}

// Returns:
// - a complete entry when parameter inference already succeeded;
// - an empty entry when parameter inference is on the way;
// - nullptr when analysis failed.
// It is possible that analysis returns an empty set, but then returns nullptr.
const CallInformation* ParameterRegistry::getCallInfo(Function &function)
{
	assert(!md::isPrototype(function));
	auto iter = aaResults->callInformation.find(&function);
	if (iter == aaResults->callInformation.end())
	{
		return analyzing ? analyzeFunction(function) : nullptr;
	}
	
	return &iter->second;
}

const CallInformation* ParameterRegistry::getDefinitionCallInfo(Function& function)
{
	assert(md::isPrototype(function));
	
	CallInformation& info = aaResults->callInformation[&function];
	if (info.getStage() == CallInformation::New)
	{
		for (CallingConvention* cc : *this)
		{
			if (cc->analyzeFunctionType(*this, info, *function.getFunctionType()))
			{
				info.setCallingConvention(cc);
				return &info;
			}
		}
	}
	else if (info.getStage() == CallInformation::Completed)
	{
		return &info;
	}
	
	return nullptr;
}

unique_ptr<CallInformation> ParameterRegistry::analyzeCallSite(CallSite callSite)
{
	unique_ptr<CallInformation> info(new CallInformation);
	for (CallingConvention* cc : ccChain)
	{
		info->setStage(CallInformation::Analyzing);
		if (cc->analyzeCallSite(*this, *info, callSite))
		{
			info->setCallingConvention(cc);
			info->setStage(CallInformation::Completed);
			return info;
		}
		else
		{
			info->setStage(CallInformation::New);
			info->clear();
		}
	}
	
	info.reset();
	return info;
}

unique_ptr<MemorySSA> ParameterRegistry::createMemorySSA(Function &function)
{
	auto& domTree = getAnalysis<DominatorTreeWrapperPass>(function).getDomTree();
	auto& aaResult = getAnalysis<AAResultsWrapperPass>(function).getAAResults();
	
	// XXX: don't explicitly depend on this other AA pass
	// This will be easier once we move over to the new pass infrastructure
	aaResult.addAAResult(*aaHack);
	
	return std::make_unique<MemorySSA>(function, &aaResult, &domTree);
}

MemorySSA* ParameterRegistry::getMemorySSA(Function &function)
{
	unsigned version = md::getFunctionVersion(function);
	auto iter = mssas.find(&function);
	if (iter == mssas.end())
	{
		auto mssa = createMemorySSA(function);
		iter = mssas.insert(make_pair(&function, make_pair(version, move(mssa)))).first;
	}
	else if (iter->second.first != version)
	{
		iter->second.first = version;
		iter->second.second = createMemorySSA(function);
	}
	return iter->second.second.get();
}

void ParameterRegistry::getAnalysisUsage(AnalysisUsage &au) const
{
	au.addRequired<AAResultsWrapperPass>();
	
	au.addRequired<DominatorTreeWrapperPass>();
	au.addPreserved<DominatorTreeWrapperPass>();
	
	au.addRequired<TargetLibraryInfoWrapperPass>();
	au.addPreserved<TargetLibraryInfoWrapperPass>();
	
	au.addRequired<PostDominatorTreeWrapperPass>();
	au.addPreserved<PostDominatorTreeWrapperPass>();
	
	au.addRequired<ExecutableWrapper>();
	au.addPreserved<ExecutableWrapper>();
	
	au.addRequired<TargetLibraryInfoWrapperPass>();
	au.addPreserved<TargetLibraryInfoWrapperPass>();
	
	for (CallingConvention* cc : CallingConvention::getCallingConventions())
	{
		cc->getAnalysisUsage(au);
	}
	
	ModulePass::getAnalysisUsage(au);
}

StringRef ParameterRegistry::getPassName() const
{
	return "Parameter Registry";
}

bool ParameterRegistry::doInitialization(Module& m)
{
	if (!(targetInfo = TargetInfo::getTargetInfo(m)))
	{
		return false;
	}
	
	return ModulePass::doInitialization(m);
}

bool ParameterRegistry::runOnModule(Module& m)
{
	aaHack.reset(new ProgramMemoryAAResult);
	setupCCChain();
	
	aaResults.reset(new ParameterRegistryAAResults(TargetInfo::getTargetInfo(m)));
	
	TemporaryTrue isAnalyzing(analyzing);
	for (auto& fn : m.getFunctionList())
	{
		if (!md::isPrototype(fn) && md::getAssemblyString(fn) == nullptr)
		{
			analyzeFunction(fn);
		}
	}
	
	return false;
}

INITIALIZE_PASS_BEGIN(ParameterRegistry, "paramreg", "ModRef info for registers", false, true)
INITIALIZE_PASS_DEPENDENCY(AAResultsWrapperPass)
INITIALIZE_PASS_DEPENDENCY(CallGraphWrapperPass)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(PostDominatorTreeWrapperPass)
INITIALIZE_PASS_END(ParameterRegistry, "paramreg", "ModRef info for registers", false, true)
