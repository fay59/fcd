//
// params_registry.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is part of fcd.
// 
// fcd is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// fcd is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with fcd.  If not, see <http://www.gnu.org/licenses/>.
//

#include "anyarch_anycc.h"
#include "anyarch_interactive.h"
#include "anyarch_lib.h"
#include "call_conv.h"
#include "command_line.h"
#include "executable.h"
#include "metadata.h"
#include "params_registry.h"
#include "pass_executable.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Analysis/PostDominators.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Module.h>
SILENCE_LLVM_WARNINGS_END()

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
		
		static inline vector<OptionInfo>& ccs()
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
					return strcmp(a.Name, b.Name) < 0;
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
		
		virtual const char* getOption(unsigned n) const override
		{
			return ccs().at(n).Name;
		}
		
		virtual const char* getDescription(unsigned n) const override
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
	addCallingConvention(CallingConvention::getCallingConvention(CallingConvention_AnyArch_Library::name));
	
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
	
	if (ccChain.size() > 1)
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
const CallInformation* ParameterRegistry::getCallInfo(llvm::Function &function)
{
	auto iter = aaResults->callInformation.find(&function);
	if (iter == aaResults->callInformation.end())
	{
		return analyzing ? analyzeFunction(function) : nullptr;
	}
	
	return &iter->second;
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

MemorySSA* ParameterRegistry::getMemorySSA(llvm::Function &function)
{
	auto iter = mssas.find(&function);
	if (iter == mssas.end())
	{
		auto mssa = std::make_unique<MemorySSA>(function);
		auto& domTree = getAnalysis<DominatorTreeWrapperPass>(function).getDomTree();
		
		// XXX: don't explicitly depend on this other AA pass
		// This will be easier once we move over to the new pass infrastructure
		auto& aaResult = getAnalysis<AAResultsWrapperPass>(function).getAAResults();
		aaResult.addAAResult(*aaHack);
		
		mssa->buildMemorySSA(&aaResult, &domTree);
		iter = mssas.insert(make_pair(&function, move(mssa))).first;
	}
	return iter->second.get();
}

void ParameterRegistry::getAnalysisUsage(llvm::AnalysisUsage &au) const
{
	au.addRequired<AAResultsWrapperPass>();
	
	au.addRequired<DominatorTreeWrapperPass>();
	au.addPreserved<DominatorTreeWrapperPass>();
	
	au.addRequired<TargetLibraryInfoWrapperPass>();
	au.addPreserved<TargetLibraryInfoWrapperPass>();
	
	au.addRequired<PostDominatorTree>();
	au.addPreserved<PostDominatorTree>();
	
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

const char* ParameterRegistry::getPassName() const
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
	auto& tli = getAnalysis<TargetLibraryInfoWrapperPass>().getTLI();
	aaHack.reset(new ProgramMemoryAAResult(tli));
	setupCCChain();
	
	auto targetInfo = TargetInfo::getTargetInfo(m);
	auto& targetLibInfo = getAnalysis<TargetLibraryInfoWrapperPass>().getTLI();
	aaResults.reset(new ParameterRegistryAAResults(targetLibInfo, move(targetInfo)));
	
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
INITIALIZE_PASS_DEPENDENCY(PostDominatorTree)
INITIALIZE_PASS_END(ParameterRegistry, "paramreg", "ModRef info for registers", false, true)
