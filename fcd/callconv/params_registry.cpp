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
#include "main.h"
#include "params_registry.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Module.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

namespace
{
	cl::opt<string> defaultCCName("cc", cl::desc("Default calling convention"), cl::value_desc("calling convention"), cl::init("auto"), whitelist());
	
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

AliasAnalysis::ModRefResult CallInformation::getRegisterModRef(const TargetRegisterInfo &reg) const
{
	// If it's a return value, then Mod;
	// if it's a parameter, then Ref;
	// otherwise, NoModRef, as far as the call information is concerned.
	// Two notable exceptions are the instruction pointer and the stack pointer, which have to be handled out of here.
	underlying_type_t<AliasAnalysis::ModRefResult> result = AliasAnalysis::NoModRef;
	auto retBegin = return_begin();
	for (auto iter = begin(); iter != end(); ++iter)
	{
		if (iter->type == ValueInformation::IntegerRegister && &reg == iter->registerInfo)
		{
			result |= iter < retBegin ? AliasAnalysis::Ref : AliasAnalysis::Mod;
		}
	}
	
	return static_cast<AliasAnalysis::ModRefResult>(result);
}

char ParameterRegistry::ID = 0;

ParameterRegistry::ParameterRegistry(TargetInfo& info, Executable& exe)
: ModulePass(ID), executable(exe)
{
	addCallingConvention(CallingConvention::getCallingConvention(CallingConvention_AnyArch_Library::name));
	
	if (defaultCCName == "auto")
	{
		if (auto cc = CallingConvention::getMatchingCallingConvention(info, executable))
		{
			addCallingConvention(cc);
		}
		else
		{
			// do something?
			assert(false);
		}
	}
	else
	{
		if (auto cc = CallingConvention::getCallingConvention(defaultCCName))
		{
			addCallingConvention(cc);
		}
		else
		{
			assert(false);
		}
	}
	
	if (isFullDisassembly())
	{
		addCallingConvention(CallingConvention::getCallingConvention(CallingConvention_AnyArch_AnyCC::name));
	}
	
	addCallingConvention(CallingConvention::getCallingConvention(CallingConvention_AnyArch_Interactive::name));
}

CallInformation* ParameterRegistry::analyzeFunction(Function& fn)
{
	CallInformation& info = callInformation[&fn];
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

// Returns:
// - a complete entry when parameter inference already succeeded;
// - an empty entry when parameter inference is on the way;
// - nullptr when analysis failed.
// It is possible that analysis returns an empty set, but then returns nullptr.
const CallInformation* ParameterRegistry::getCallInfo(llvm::Function &function)
{
	auto iter = callInformation.find(&function);
	if (iter == callInformation.end())
	{
		return analyzing ? analyzeFunction(function) : nullptr;
	}
	
	return &iter->second;
}

MemorySSA* ParameterRegistry::getMemorySSA(llvm::Function &function)
{
	if (!analyzing)
	{
		return nullptr;
	}
	
	auto iter = mssas.find(&function);
	if (iter == mssas.end())
	{
		auto mssa = std::make_unique<MemorySSA>(function);
		auto& domTree = getAnalysis<DominatorTreeWrapperPass>(function).getDomTree();
		mssa->buildMemorySSA(&getAnalysis<AliasAnalysis>(), &domTree);
		iter = mssas.insert(make_pair(&function, move(mssa))).first;
	}
	return iter->second.get();
}

void ParameterRegistry::getAnalysisUsage(llvm::AnalysisUsage &au) const
{
	au.addRequired<AliasAnalysis>();
	au.addRequired<DominatorTreeWrapperPass>();
	au.addRequired<PostDominatorTree>();
	au.addRequired<TargetInfo>();
	
	for (CallingConvention* cc : ccChain)
	{
		cc->getAnalysisUsage(au);
	}
	
	AliasAnalysis::getAnalysisUsage(au);
	ModulePass::getAnalysisUsage(au);
	au.setPreservesAll();
}

const char* ParameterRegistry::getPassName() const
{
	return "Parameter Registry";
}

bool ParameterRegistry::runOnModule(Module& m)
{
	InitializeAliasAnalysis(this, &m.getDataLayout());
	
	TemporaryTrue isAnalyzing(analyzing);
	for (auto& fn : m.getFunctionList())
	{
		if (!fn.isDeclaration())
		{
			analyzeFunction(fn);
		}
	}
	
	mssas.clear();
	return false;
}

void* ParameterRegistry::getAdjustedAnalysisPointer(llvm::AnalysisID PI)
{
	if (PI == &AliasAnalysis::ID)
		return (AliasAnalysis*)this;
	return this;
}

AliasAnalysis::ModRefResult ParameterRegistry::getModRefInfo(llvm::ImmutableCallSite cs, const llvm::MemoryLocation &location)
{
	if (auto inst = dyn_cast<CallInst>(cs.getInstruction()))
	{
		auto iter = callInformation.find(inst->getCalledFunction());
		if (iter != callInformation.end())
		{
			const auto& target = getAnalysis<TargetInfo>();
			if (const TargetRegisterInfo* info = target.registerInfo(*location.Ptr))
			{
				return iter->second.getRegisterModRef(*info);
			}
		}
	}
	
	return AliasAnalysis::getModRefInfo(cs, location);
}

namespace llvm
{
	template<>
	Pass *callDefaultCtor<ParameterRegistry>()
	{
		// This shouldn't be called.
		assert(false);
		return nullptr;
	}
}

INITIALIZE_AG_PASS_BEGIN(ParameterRegistry, AliasAnalysis, "paramreg", "ModRef info for registers", true, true, false)
INITIALIZE_PASS_DEPENDENCY(TargetInfo)
INITIALIZE_PASS_DEPENDENCY(CallGraphWrapperPass)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(MemorySSALazy)
INITIALIZE_PASS_DEPENDENCY(PostDominatorTree)
INITIALIZE_AG_PASS_END(ParameterRegistry, AliasAnalysis, "paramreg", "ModRef info for registers", true, true, false)
