//
// pass_asaa.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

// This file is borrowed and recycled from a patch from Justin Holewinski that
// never made it to the main repository.
// http://lists.cs.uiuc.edu/pipermail/llvm-commits/Week-of-Mon-20111010/129632.html

#include "metadata.h"
#include "pass_regaa.h"
#include "passes.h"

#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

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
	result.reset(new ProgramMemoryAAResult);
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

char ProgramMemoryAAWrapperPass::ID = 0;
static RegisterPass<ProgramMemoryAAWrapperPass> asaa("#asaa", "NoAlias for pointers in different address spaces", false, true);

ImmutablePass* createProgramMemoryAliasAnalysis()
{
	return new ProgramMemoryAAWrapperPass;
}
