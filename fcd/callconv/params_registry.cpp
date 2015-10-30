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

#include "call_conv.h"
#include "command_line.h"
#include "executable.h"
#include "params_registry.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/SCCIterator.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/Dominators.h>
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
			if (value.type == ValueInformation::IntegerRegister && reg.name == value.registerName)
			{
				return true;
			}
		}
		return false;
	}
}

AliasAnalysis::ModRefResult CallInformation::getRegisterModRef(const TargetRegisterInfo &reg) const
{
	// If it's a return value, then Mod;
	// if it's a parameter, then Ref;
	// otherwise, NoModRef, as far as the call information is concerned.
	// Two notable exceptions are the instruction pointer and the stack pointer, which have to be handled out of here.
	underlying_type_t<AliasAnalysis::ModRefResult> result = AliasAnalysis::NoModRef;
	if (findReg(reg, returnValues))
	{
		result |= AliasAnalysis::Mod;
	}
	if (findReg(reg, parameters))
	{
		result |= AliasAnalysis::Ref;
	}
	return static_cast<AliasAnalysis::ModRefResult>(result);
}

char ParameterRegistry::ID = 0;

ParameterRegistry::ParameterRegistry(TargetInfo& info, Executable& executable)
: ModulePass(ID), target(info), executable(executable)
{
	if (defaultCCName == "auto")
	{
		defaultCC = CallingConvention::getMatchingCallingConvention(info, executable);
	}
	else if (auto cc = CallingConvention::getCallingConvention(defaultCCName))
	{
		defaultCC = cc;
	}
	else
	{
		// replace with ErrorOr<>
		assert(false);
	}
}

// Returns:
// - a complete entry when parameter inference already succeeded;
// - an empty entry when parameter inference is on the way;
// - nullptr when analysis failed.
// It is possible that analysis returns an empty set, but then returns nullptr.
const CallInformation* ParameterRegistry::getCallInfo(llvm::Function &function) const
{
	auto iter = callInformation.find(&function);
	if (iter == callInformation.end())
	{
		return nullptr;
	}
	
	return &iter->second;
}

CallInformation* ParameterRegistry::createCallInfo(llvm::Function &function, const char *ccName)
{
	bool newElement;
	unordered_map<const Function*, CallInformation>::iterator iter;
	tie(iter, newElement) = callInformation.insert(make_pair(&function, CallInformation(ccName)));
	
	if (newElement)
	{
		return &iter->second;
	}
	
	return nullptr;
}

CallingConvention* ParameterRegistry::getCallingConvention(llvm::Function &function)
{
	// This should eventually be made more useful.
	return defaultCC;
}

void ParameterRegistry::getAnalysisUsage(llvm::AnalysisUsage &au) const
{
	au.addRequired<AliasAnalysis>();
	au.addRequired<CallGraphWrapperPass>();
	au.addRequired<DominatorTreeWrapperPass>();
	au.addRequired<PostDominatorTree>();
	au.addRequired<TargetInfo>();
	
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

bool ParameterRegistry::runOnModule(Module& m)
{
	return false;
}
