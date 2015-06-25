//
//  program_output.cpp
//  x86Emulator
//
//  Created by Félix on 2015-06-16.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#include "program_output.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/PostOrderiterator.h>
#include <llvm/Analysis/PostDominators.h>
SILENCE_LLVM_WARNINGS_END()

#include <unordered_set>

using namespace llvm;
using namespace std;

char AstBackEnd::ID = 0;

void AstBackEnd::getAnalysisUsage(llvm::AnalysisUsage &au) const
{
	au.addRequired<LoopInfoWrapperPass>();
	au.addRequired<RegionInfoPass>();
	au.setPreservesAll();
}

bool AstBackEnd::runOnModule(llvm::Module &m)
{
	return false;
}

bool AstBackEnd::runOnFunction(llvm::Function& fn)
{
	// sanity checks
	auto iter = astPerFunction.find(&fn);
	if (iter != astPerFunction.end())
	{
		return false;
	}
	
	if (fn.empty())
	{
		return false;
	}
	
	bool changed = false;
	
	// Identify loops, then visit basic blocks in post-order. If the basic block if the head
	// of a cyclic region, process the loop. Else, if the basic block is the start of a single-entry-single-exit
	// region, process that region.
	
	LoopInfo& loopInfo = getAnalysis<LoopInfoWrapperPass>(fn).getLoopInfo();
	RegionInfo& regionInfo = getAnalysis<RegionInfoPass>().getRegionInfo();
	
	for (BasicBlock* block : post_order(&fn.getEntryBlock()))
	{
		if (loopInfo.isLoopHeader(block))
		{
			changed |= runOnLoop(*loopInfo.getLoopFor(block));
		}
		else
		{
			Region* region = regionInfo.getRegionFor(block);
			if (region->getEntry() == block)
			{
				changed |= runOnRegion(*region);
			}
		}
	}
	
	return changed;
}

bool AstBackEnd::runOnLoop(Loop& loop)
{
	return false;
}

bool AstBackEnd::runOnRegion(Region& region)
{
	return false;
}
