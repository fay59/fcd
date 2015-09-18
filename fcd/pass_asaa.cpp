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

#include <iostream>

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include "passes.h"

using namespace llvm;

namespace
{
	struct AddressSpaceAliasAnalysis : public ImmutablePass, public AliasAnalysis
	{
		static char ID;
		AddressSpaceAliasAnalysis() : ImmutablePass(ID)
		{
		}
		
		virtual bool doInitialization(Module& m) override
		{
			InitializeAliasAnalysis(this, &m.getDataLayout());
			return true;
		}
		
		virtual void getAnalysisUsage(AnalysisUsage &AU) const override
		{
			AliasAnalysis::getAnalysisUsage(AU);
		}
		
		virtual AliasResult alias(const MemoryLocation &LocA, const MemoryLocation &LocB) override
		{
			const PointerType& PT1 = *cast<const PointerType>(LocA.Ptr->getType());
			const PointerType& PT2 = *cast<const PointerType>(LocB.Ptr->getType());
			
			// The logic here is very simple: pointers to two different address spaces
			// cannot alias.
			if (PT1.getAddressSpace() != PT2.getAddressSpace())
			{
				return NoAlias;
			}
			
			return AliasAnalysis::alias(LocA, LocB);
		}
		
		virtual void *getAdjustedAnalysisPointer(AnalysisID PI) override
		{
			if (PI == &AliasAnalysis::ID)
				return (AliasAnalysis*)this;
			return this;
		}
	};
	
	// Register this pass...
	char AddressSpaceAliasAnalysis::ID = 0;
	
	static RegisterPass<AddressSpaceAliasAnalysis> asaa("asaa", "NoAlias for pointers in different address spaces", false, true);
	static RegisterAnalysisGroup<AliasAnalysis> aag(asaa);
}

ImmutablePass* createAddressSpaceAliasAnalysisPass() {
	return new AddressSpaceAliasAnalysis;
}
