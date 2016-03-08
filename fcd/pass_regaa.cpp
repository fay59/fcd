//
// pass_asaa.cpp
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

// This file is borrowed and recycled from a patch from Justin Holewinski that
// never made it to the main repository.
// http://lists.cs.uiuc.edu/pipermail/llvm-commits/Week-of-Mon-20111010/129632.html

#include "llvm_warnings.h"
#include "metadata.h"
#include "passes.h"
#include "pass_regaa.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
SILENCE_LLVM_WARNINGS_END()

#include <memory>

using namespace llvm;
using namespace std;

namespace
{
	bool isProgramMemory(const Value& pointer)
	{
		for (const User* user : pointer.users())
		{
			if (auto inst = dyn_cast<Instruction>(user))
			if (inst->getOpcode() == Instruction::Load || inst->getOpcode() == Instruction::Store)
			{
				return md::isProgramMemory(*inst);
			}
		}
		return false;
	}
}

AliasResult ProgramMemoryAAResult::alias(const MemoryLocation& a, const MemoryLocation& b)
{
	if (isProgramMemory(*a.Ptr) != isProgramMemory(*b.Ptr))
	{
		return NoAlias;
	}
	return AAResultBase::alias(a, b);
}

ProgramMemoryAAWrapperPass::ProgramMemoryAAWrapperPass()
: ImmutablePass(ID)
{
}

ProgramMemoryAAWrapperPass::~ProgramMemoryAAWrapperPass()
{
}

ProgramMemoryAAResult& ProgramMemoryAAWrapperPass::getResult()
{
	return *result;
}

const ProgramMemoryAAResult& ProgramMemoryAAWrapperPass::getResult() const
{
	return *result;
}

bool ProgramMemoryAAWrapperPass::doInitialization(Module& m)
{
	auto& tli = getAnalysis<TargetLibraryInfoWrapperPass>().getTLI();
	result.reset(new ProgramMemoryAAResult(tli));
	return false;
}

bool ProgramMemoryAAWrapperPass::doFinalization(Module& m)
{
	result.reset();
	return false;
}

void ProgramMemoryAAWrapperPass::getAnalysisUsage(AnalysisUsage& au) const
{
	au.addRequired<TargetLibraryInfoWrapperPass>();
	au.setPreservesAll();
}

// Register this pass...
char ProgramMemoryAAWrapperPass::ID = 0;
static RegisterPass<ProgramMemoryAAWrapperPass> asaa("asaa", "NoAlias for pointers in different address spaces", false, true);

ImmutablePass* createProgramMemoryAliasAnalysis()
{
	return new ProgramMemoryAAWrapperPass;
}
