//
// pass_memssa_dle.cpp
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

#include "passes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/PostOrderIterator.h>
#include <llvm/IR/PatternMatch.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

namespace
{
	struct MemorySSADLE final : public FunctionPass
	{
		static char ID;
		
		MemorySSADLE() : FunctionPass(ID)
		{
		}
		
		virtual const char* getPassName() const override
		{
			return "Dead Load Elimination";
		}
		
		virtual void getAnalysisUsage(AnalysisUsage& au) const override
		{
			au.addRequired<AAResultsWrapperPass>();
			au.addRequired<DominatorTreeWrapperPass>();
			au.setPreservesAll();
		}
		
		bool runOnBasicBlock(MemorySSA& mssa, BasicBlock& bb)
		{
			bool changed = false;
			SmallVector<LoadInst*, 10> deletedLoads;
			if (auto accessList = mssa.getBlockAccesses(&bb))
			{
				for (const MemoryAccess& access : *accessList)
				{
					if (auto use = dyn_cast<MemoryUse>(&access))
					if (auto load = dyn_cast<LoadInst>(use->getMemoryInst()))
					{
						auto parent = access.getDefiningAccess();
						if (isa<MemoryDef>(parent))
						if (auto store = dyn_cast_or_null<StoreInst>(parent->getMemoryInst()))
						{
							auto storedValue = store->getValueOperand();
							// sanity test
							if (storedValue->getType() == load->getType())
							{
								load->replaceAllUsesWith(storedValue);
								deletedLoads.push_back(load);
								changed = true;
							}
						}
					}
				}
			}
			
			for (LoadInst* deletedLoad : deletedLoads)
			{
				auto access = mssa.getMemoryAccess(deletedLoad);
				assert(access != nullptr);
				deletedLoad->eraseFromParent();
				mssa.removeMemoryAccess(access);
			}
			
			return changed;
		}
		
		virtual bool runOnFunction(Function& f) override
		{
			MemorySSA mssa(f);
			auto& aaResults = getAnalysis<AAResultsWrapperPass>().getAAResults();
			auto& domTree = getAnalysis<DominatorTreeWrapperPass>().getDomTree();
			mssa.buildMemorySSA(&aaResults, &domTree);
			bool changed = false;
			for (BasicBlock* bb : ReversePostOrderTraversal<BasicBlock*>(&f.getEntryBlock()))
			{
				changed |= runOnBasicBlock(mssa, *bb);
			}
			return changed;
		}
	};
	
	char MemorySSADLE::ID = 0;
	
	RegisterPass<MemorySSADLE> memSsaDle("memssadle", "MemorySSA-based dead load elimination");
}

FunctionPass* createMemorySSADeadLoadEliminationPass()
{
	return new MemorySSADLE;
}
