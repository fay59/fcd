//
//  pass_seseloop.cpp
//  x86Emulator
//
//  Created by Félix on 2015-07-05.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#include "llvm_warnings.h"
#include "passes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/PostOrderIterator.h>
#include <llvm/IR/Constants.h>
SILENCE_LLVM_WARNINGS_END()

#include <deque>
#include <unordered_map>

using namespace llvm;
using namespace std;

namespace
{
	template<typename TGraphType, typename GraphTr = GraphTraits<TGraphType>>
	void buildGraphSlice(TGraphType currentNode, const unordered_set<TGraphType>& sinkNodes, vector<vector<TGraphType>>& results, deque<TGraphType>& stack)
	{
		stack.push_back(currentNode);
		
		if (sinkNodes.count(currentNode) == 1)
		{
			results.emplace_back(stack.begin(), stack.end());
		}
		
		auto end = GraphTr::child_end(currentNode);
		for (auto iter = GraphTr::child_begin(currentNode); iter != end; ++iter)
		{
			TGraphType explored = *iter;
			bool found = any_of(stack.rbegin(), stack.rend(), [&](const TGraphType& item)
			{
				return explored == item;
			});
			
			if (!found)
			{
				buildGraphSlice(explored, sinkNodes, results, stack);
			}
		}
		stack.pop_back();
	}
	
	template<typename TGraphType, typename GraphTr = GraphTraits<TGraphType>>
	vector<vector<TGraphType>> buildGraphSlice(TGraphType startNode, const unordered_set<TGraphType>& sinkNodes)
	{
		vector<vector<TGraphType>> result;
		deque<TGraphType> stack;
		buildGraphSlice(startNode, sinkNodes, result, stack);
		return result;
	}
	
	void findBackEdgeDestinations(BasicBlock* entry, deque<BasicBlock*>& stack, unordered_multimap<BasicBlock*, BasicBlock*>& result)
	{
		stack.push_back(entry);
		for (BasicBlock* bb : successors(entry))
		{
			if (find(stack.rbegin(), stack.rend(), bb) == stack.rend())
			{
				findBackEdgeDestinations(bb, stack, result);
			}
			else
			{
				result.insert({bb, entry});
			}
		}
		stack.pop_back();
	}
	
	unordered_multimap<BasicBlock*, BasicBlock*> findBackEdgeDestinations(BasicBlock& entryPoint)
	{
		unordered_multimap<BasicBlock*, BasicBlock*> result;
		deque<BasicBlock*> visitedStack;
		findBackEdgeDestinations(&entryPoint, visitedStack, result);
		return result;
	}
	
	struct SESELoop : public FunctionPass
	{
		static char ID;
		
		uint64_t redirected;
		BasicBlock* singleExit;
		IntegerType* intTy;
		PHINode* phiNode;
		
		deque<BasicBlock*> redirections;
		unordered_map<BasicBlock*, ConstantInt*> caseIds;
		
		unordered_multimap<BasicBlock*, BasicBlock*> backEdges;
		
		SESELoop() : FunctionPass(ID)
		{
		}
		
		virtual void getAnalysisUsage(AnalysisUsage& au) const override
		{
			au.addRequired<DominatorTreeWrapperPass>();
		}
		
		virtual bool runOnFunction(Function& fn) override
		{
			if (fn.isDeclaration())
			{
				return false;
			}
			
			bool changed = false;
			backEdges = findBackEdgeDestinations(fn.getEntryBlock());
			
			vector<BasicBlock*> postOrder;
			for (BasicBlock* bb : post_order(&fn.getEntryBlock()))
			{
				if (backEdges.count(bb) != 0)
				{
					postOrder.push_back(bb);
				}
			}
			
			for (BasicBlock* bb : postOrder)
			{
				changed |= runOnCycle(*bb);
			}
			
			return changed;
		}
		
		virtual bool runOnCycle(BasicBlock& entry)
		{
			bool changed = false;
			
			// Build graph slice
			unordered_set<BasicBlock*> sinkNodeSet;
			auto range = backEdges.equal_range(&entry);
			for (auto iter = range.first; iter != range.second; iter++)
			{
				sinkNodeSet.insert(iter->second);
			}
			
			auto graphSlice = buildGraphSlice(&entry, sinkNodeSet);
			
			// Build initial loop membership set
			unordered_set<BasicBlock*> members;
			for (const auto& path : graphSlice)
			{
				members.insert(path.begin(), path.end());
			}
			
			unordered_set<BasicBlock*> entries; // nodes inside the loop that are reached from the outside
			unordered_set<BasicBlock*> enteringNodes; // nodes outside the loop going into the loop
			unordered_set<BasicBlock*> exits; // nodes outside the loop that are preceded by a node inside of it
			for (BasicBlock* member : members)
			{
				for (BasicBlock* pred : predecessors(member))
				{
					if (members.count(pred) == 0)
					{
						entries.insert(member);
						enteringNodes.insert(pred);
					}
				}
				
				for (BasicBlock* succ : successors(member))
				{
					if (members.count(succ) == 0)
					{
						exits.insert(succ);
					}
				}
			}

			// The "No More Gotos" paper suggests a step of "loop membership refinement", but it seems dubiously useful
			// to me. I could have done it wrong, but from my experience, it'll just gobble up non-looping nodes and
			// stick a break statement after them. Git commit 9b2f84f9bb5ab5348f7dc8548474442622de5114 has the last
			// revision of this file before I removed the loop membership refinement step.
			
			if (entries.size() > 1)
			{
				// Fix abnormal entries. This will also require a change to every predecessor of the entry node.
				for (BasicBlock* pred : predecessors(&entry))
				{
					enteringNodes.insert(pred);
				}
				
				createFunnelBlock(enteringNodes, [&](BasicBlock* bb) { return members.count(bb) != 0; });
				changed = true;
			}
			
			if (exits.size() > 1)
			{
				// Fix abnormal exits.
				// Find in-loop predecessors.
				unordered_set<BasicBlock*> exitPreds;
				for (BasicBlock* exit : exits)
				{
					for (BasicBlock* pred : predecessors(exit))
					{
						if (members.count(pred) != 0)
						{
							exitPreds.insert(pred);
						}
					}
				}
				
				// Funnel to single exit.
				createFunnelBlock(exitPreds, [&](BasicBlock* bb) { return members.count(bb) == 0; });
				changed = true;
			}
			
			return changed;
		}
		
		void createFunnelBlock(const unordered_set<BasicBlock*>& predecessors, const function<bool(BasicBlock*)>& shouldFunnel)
		{
			BasicBlock* anyBB = *predecessors.begin();
			LLVMContext& ctx = anyBB->getContext();
			Function* fn = anyBB->getParent();
			
			// Introduce funnel basic block, PHI node and switch terminator.
			singleExit = BasicBlock::Create(ctx, "sese.funnel", fn);
			intTy = Type::getInt32Ty(ctx);
			
			auto truncatedBlocksCount = static_cast<unsigned>(predecessors.size());
			phiNode = PHINode::Create(intTy, truncatedBlocksCount, "", singleExit);
			redirected = 0;
			redirections.clear();
			caseIds.clear();
			
			// Redirect blocks.
			for (BasicBlock* enteringBlock : predecessors)
			{
				auto terminator = enteringBlock->getTerminator();
				if (auto branch = dyn_cast<BranchInst>(terminator))
				{
					fixBranchInst(branch, shouldFunnel);
				}
				else
				{
					assert(isa<ReturnInst>(terminator) && "implement other terminator insts");
				}
			}
			
			// Create cascading if conditions.
			BranchInst* lastBranch = nullptr;
			BasicBlock* endBlock = singleExit;
			assert(redirections.size() > 0);
			for (size_t i = 0; i < redirections.size() - 1; i++)
			{
				BasicBlock* next = BasicBlock::Create(ctx, "sese.funnel.cascade", fn);
				ConstantInt* key = ConstantInt::get(intTy, i);
				Value* comp = new ICmpInst(*endBlock, ICmpInst::ICMP_EQ, phiNode, key);
				lastBranch = BranchInst::Create(redirections[i], next, comp, endBlock);
				endBlock = next;
			}
			
			lastBranch->setSuccessor(1, redirections.back());
			endBlock->eraseFromParent();
		}
		
		void fixBranchInst(BranchInst* branch, const function<bool(BasicBlock*)>& shouldFunnel)
		{
			if (shouldFunnel(branch->getSuccessor(0)))
			{
				fixBranchSuccessor(branch, 0);
				
				// Are both successors outside the loop? if so, we'll run into problems with the PHINode
				// scheme. Insert additional dummy block inside of loop.
				if (branch->isConditional())
				{
					auto falseSucc = branch->getSuccessor(1);
					if (shouldFunnel(falseSucc))
					{
						BasicBlock* dummyExitingBlock = BasicBlock::Create(falseSucc->getContext(), "sese.dummy", falseSucc->getParent(), falseSucc);
						BranchInst* dummyBranch = BranchInst::Create(falseSucc, dummyExitingBlock);
						branch->setSuccessor(1, dummyExitingBlock);
						fixBranchInst(dummyBranch, shouldFunnel);
					}
				}
			}
			else if (branch->isConditional())
			{
				if (shouldFunnel(branch->getSuccessor(1)))
				{
					fixBranchSuccessor(branch, 1);
				}
			}
		}
		
		void fixBranchSuccessor(BranchInst* branch, unsigned successor)
		{
			BasicBlock* exit = branch->getSuccessor(successor);
			auto iter = caseIds.find(exit);
			
			ConstantInt* phiValue;
			if (iter == caseIds.end())
			{
				phiValue = ConstantInt::get(intTy, redirected);
				caseIds.insert({exit, phiValue});
				redirections.push_back(exit);
				redirected++;
			}
			else
			{
				phiValue = iter->second;
			}
			
			branch->setSuccessor(successor, singleExit);
			phiNode->addIncoming(phiValue, branch->getParent());
		}
	};
	
	char SESELoop::ID = 0;
}

FunctionPass* createSESELoopPass()
{
	return new SESELoop;
}

INITIALIZE_PASS_BEGIN(SESELoop, "seselopp", "Turn SimplifyLoop-formed loops into single-entry, single-exit loops", true, false)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_END(SESELoop, "seselopp", "Turn SimplifyLoop-formed loops into single-entry, single-exit loops", true, false)
