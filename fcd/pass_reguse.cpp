//
// pass_reguse.cpp
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

#include "llvm_warnings.h"

#include <iostream>

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/SCCIterator.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/MemoryDependenceAnalysis.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/Analysis/RegionPass.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_os_ostream.h>
#include "MemorySSA.h"
SILENCE_LLVM_WARNINGS_END()

#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "pass_reguse.h"
#include "x86_register_map.h"

using namespace llvm;
using namespace std;

namespace
{
	template<typename T, size_t N>
	constexpr size_t countof(T (&)[N])
	{
		return N;
	}
	
	const char* modRefAsString(AliasAnalysis::ModRefResult mrb)
	{
		static const char* const modRefStrings[] = {
			[AliasAnalysis::NoModRef] = "-",
			[AliasAnalysis::Mod] = "mod",
			[AliasAnalysis::Ref] = "ref",
			[AliasAnalysis::ModRef] = "modref",
			[4] = "(incomplete) ref",
		};
		return modRefStrings[mrb];
	}
}

RegisterUse::RegisterUse()
: ImmutablePass(ID)
{
}

RegisterUse::RegisterUse(const RegisterUse& that)
: ImmutablePass(ID), registerUse(that.registerUse)
{
}

bool RegisterUse::doInitialization(Module& m)
{
	InitializeAliasAnalysis(this, &m.getDataLayout());
	return ImmutablePass::doInitialization(m);
}

const char* RegisterUse::getPassName() const
{
	return "Function Argument Registry";
}

void RegisterUse::getAnalysisUsage(llvm::AnalysisUsage& au) const
{
	AliasAnalysis::getAnalysisUsage(au);
	au.addRequired<TargetInfo>();
	au.setPreservesAll();
}

void* RegisterUse::getAdjustedAnalysisPointer(llvm::AnalysisID PI)
{
	if (PI == &AliasAnalysis::ID)
		return (AliasAnalysis*)this;
	return this;
}

unordered_map<const char*, RegisterUse::ModRefResult>& RegisterUse::getOrCreateModRefInfo(llvm::Function *fn)
{
	return registerUse[fn];
}

unordered_map<const char*, RegisterUse::ModRefResult>* RegisterUse::getModRefInfo(llvm::Function *fn)
{
	auto iter = registerUse.find(fn);
	return iter == registerUse.end() ? nullptr : &iter->second;
}

const unordered_map<const char*, RegisterUse::ModRefResult>* RegisterUse::getModRefInfo(llvm::Function *fn) const
{
	auto iter = registerUse.find(fn);
	return iter == registerUse.end() ? nullptr : &iter->second;
}

RegisterUse::ModRefResult RegisterUse::getModRefInfo(llvm::Function *fn, const char *registerName) const
{
	auto iter = registerUse.find(fn);
	if (iter != registerUse.end())
	{
		const char* canon = getAnalysis<TargetInfo>().keyName(registerName);
		auto regIter = iter->second.find(canon);
		if (regIter != iter->second.end())
		{
			return regIter->second;
		}
	}
	return NoModRef;
}

RegisterUse::ModRefResult RegisterUse::getModRefInfo(ImmutableCallSite cs, const MemoryLocation& location)
{
	if (auto inst = dyn_cast<CallInst>(cs.getInstruction()))
	{
		auto iter = registerUse.find(inst->getCalledFunction());
		// The data here is incomplete when used for recursive calls. Any register that isn't trivially declared
		// Mod is declared Ref only. This is on purpose, as it allows us to bypass recursive calls to determine
		// if, notwithstanding the call itself, the function can modify the queried register.
		if (iter != registerUse.end())
		{
			const auto& target = getAnalysis<TargetInfo>();
			const char* maybeName = target.registerName(*location.Ptr);
			const char* registerName = target.largestOverlappingRegister(maybeName);
			auto regIter = iter->second.find(registerName);
			return regIter == iter->second.end() ? NoModRef : regIter->second;
		}
	}
	
	// no idea
	return AliasAnalysis::getModRefInfo(cs, location);
}

#pragma mark DEBUG
void RegisterUse::dumpFn(const Function* fn) const
{
	cout << fn->getName().str() << endl;
	auto iter = registerUse.find(fn);
	if (iter != registerUse.end())
	{
		for (auto& pair : iter->second)
		{
			cout << pair.first << ": " << modRefAsString(pair.second) << endl;
		}
	}
	cout << endl;
}

char RegisterUse::ID = 0;

INITIALIZE_AG_PASS_BEGIN(RegisterUse, AliasAnalysis, "reguse", "ModRef info for registers", true, true, false)
INITIALIZE_PASS_DEPENDENCY(TargetInfo)
INITIALIZE_PASS_DEPENDENCY(CallGraphWrapperPass)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(MemorySSALazy)
INITIALIZE_PASS_DEPENDENCY(PostDominatorTree)
INITIALIZE_AG_PASS_END(RegisterUse, AliasAnalysis, "reguse", "ModRef info for registers", true, true, false)

RegisterUse* createRegisterUsePass()
{
	return new RegisterUse;
}

