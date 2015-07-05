//
//  pass_seseloop.cpp
//  x86Emulator
//
//  Created by Félix on 2015-07-05.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

// This class takes "simplified loops" (as transformed by the LoopSimplify pass) and transform them into single-entry,
// single-exit loops. When a loop has multiple exit nodes, a single successor is introduced that uses a PHI node to
// determine where a switch statement should branch to.

#include "llvm_warnings.h"
#include "passes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Constants.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

namespace
{
	IntegerType* mostAppropriateIntegerType(LLVMContext& ctx, size_t count)
	{
		if (count < 0x100)
		{
			return Type::getInt8Ty(ctx);
		}
		if (count < 0x10000)
		{
			return Type::getInt16Ty(ctx);
		}
		if (count < 0x100000000ull)
		{
			return Type::getInt32Ty(ctx);
		}
		return Type::getInt64Ty(ctx);
	}
	
	struct SESELoop : public LoopPass
	{
		static char ID;
		
		uint64_t redirected;
		BasicBlock* singleExit;
		IntegerType* intTy;
		PHINode* phiNode;
		SwitchInst* singleExitSwitch;
		
		SESELoop() : LoopPass(ID)
		{
		}
		
		virtual bool runOnLoop(Loop* loop, LPPassManager& lpm) override
		{
			if (!loop->isLoopSimplifyForm())
			{
				// Early exit if the loop isn't in its simplified form. Assert on debug builds.
				assert(false);
				return false;
			}
			
			if (loop->getExitBlock() != nullptr)
			{
				// Early exit if the loop is already a single-entry, single-exit loop.
				return false;
			}
			
			SmallVector<BasicBlock*, 4> exitingBlocks;
			loop->getExitingBlocks(exitingBlocks);
			size_t exitingBlocksCount = exitingBlocks.size();
			
			LLVMContext& ctx = exitingBlocks[0]->getContext();
			Function* fn = exitingBlocks[0]->getParent();
			
			// Introduce exit basic block, PHI node and switch terminator.
			singleExit = BasicBlock::Create(ctx, "loop.single.exit", fn, exitingBlocks[0]);
			intTy = mostAppropriateIntegerType(ctx, exitingBlocksCount);
			auto truncatedBlocksCount = static_cast<unsigned>(exitingBlocksCount);
			phiNode = PHINode::Create(intTy, truncatedBlocksCount, "", singleExit);
			singleExitSwitch = SwitchInst::Create(phiNode, nullptr, truncatedBlocksCount, singleExit);
			redirected = 0;
			
			// Redirect exiting blocks.
			for (BasicBlock* exiting : exitingBlocks)
			{
				auto terminator = exiting->getTerminator();
				if (auto branch = dyn_cast<BranchInst>(terminator))
				{
					fixBranchInst(loop, branch);
				}
				else
				{
					assert(isa<ReturnInst>(terminator) && "implement missing terminator types");
				}
			}
			return true;
		}
		
		void fixBranchInst(Loop* loop, BranchInst* branch)
		{
			if (!loop->contains(branch->getSuccessor(0)))
			{
				fixBranchSuccessor(branch, 0);
				
				// Are both successors outside the loop? if so, we'll run into problems with the PHINode
				// scheme. Insert additional dummy block inside of loop.
				if (branch->isConditional())
				{
					auto falseSucc = branch->getSuccessor(1);
					if (!loop->contains(falseSucc))
					{
						BasicBlock* dummyExitingBlock = BasicBlock::Create(falseSucc->getContext(), "loop.dummy.exiting", falseSucc->getParent(), falseSucc);
						BranchInst* dummyBranch = BranchInst::Create(falseSucc, dummyExitingBlock);
						branch->setSuccessor(1, dummyExitingBlock);
						fixBranchInst(loop, dummyBranch);
					}
				}
			}
			else if (branch->isConditional())
			{
				if (!loop->contains(branch->getSuccessor(1)))
				{
					fixBranchSuccessor(branch, 1);
				}
			}
		}
		
		void fixBranchSuccessor(BranchInst* branch, unsigned successor)
		{
			ConstantInt* phiValue = ConstantInt::get(intTy, redirected);
			BasicBlock* exiting = branch->getParent();
			BasicBlock* exit = branch->getSuccessor(successor);
			
			branch->setSuccessor(successor, singleExit);
			phiNode->addIncoming(phiValue, exiting);
			singleExitSwitch->addCase(phiValue, exit);
			redirected++;
		}
	};
	
	char SESELoop::ID = 0;
}

LoopPass* createSESELoopPass()
{
	return new SESELoop;
}

INITIALIZE_PASS(SESELoop, "seselopp", "Turn SimplifyLoop-formed loops into single-entry, single-exit loops", true, false)
