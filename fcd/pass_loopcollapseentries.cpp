//
// pass_loopcollapseentries.cpp
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

//
// The purpose of this pass is to transform loops with multiple entries into single-entry loops. Then, we can use
// LoopSimplify to turn then into single-entry, single-exit loops with a single back edge.
// LoopSimplify does not work on multiple-entry loops, probably because you need to arbitrarily pick one edge to
// be the back edge. This is what this pass does.
//
// Interestingly, the No More Gotos paper did not mention this issue or the repercussions that the choice could
// have on the readability of the output.
//
// Side note: I don't understand SSAUpdater, but I have a hunch that this is what it's for, so if you want to give
// it a shot, please do.
//

#include "llvm_warnings.h"
#include "passes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/PostOrderIterator.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <deque>
#include <iostream>
#include <unordered_map>

using namespace llvm;
using namespace std;

template<typename TColl>
void dump(const TColl& coll)
{
	raw_os_ostream rerr(cerr);
	for (BasicBlock* bb : coll)
	{
		bb->printAsOperand(rerr);
		rerr << '\n';
	}
}

void dump(const deque<BasicBlock*>& stack)
{
	dump<const deque<BasicBlock*>&>(stack);
}

void dump(const unordered_set<BasicBlock*>& set)
{
	dump<const unordered_set<BasicBlock*>&>(set);
}

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
	
	void findBackEdgeDestinations(BasicBlock* entry, deque<BasicBlock*>& stack, unordered_multimap<BasicBlock*, BasicBlock*>& result, unordered_set<BasicBlock*>& visited)
	{
		visited.insert(entry);
		stack.push_back(entry);
		for (BasicBlock* bb : successors(entry))
		{
			if (visited.count(bb) == 0)
			{
				findBackEdgeDestinations(bb, stack, result, visited);
			}
			else if (find(stack.rbegin(), stack.rend(), bb) != stack.rend())
			{
				result.insert({bb, entry});
			}
		}
		stack.pop_back();
	}
	
	unordered_multimap<BasicBlock*, BasicBlock*> findBackEdgeDestinations(BasicBlock& entryPoint)
	{
		unordered_set<BasicBlock*> visited;
		unordered_multimap<BasicBlock*, BasicBlock*> result;
		deque<BasicBlock*> visitedStack;
		findBackEdgeDestinations(&entryPoint, visitedStack, result, visited);
		return result;
	}
	
	struct MutableBasicBlockEdge
	{
		BasicBlock* start;
		BasicBlock* end;
		
		MutableBasicBlockEdge(BasicBlock* start, BasicBlock* end)
		: start(start), end(end)
		{
		}
	};
	
	struct LoopCollapseEntries : public FunctionPass
	{
		static char ID;
		
		BasicBlock* singleEntry;
		IntegerType* intTy;
		PHINode* phiNode;
		unordered_map<BasicBlock*, ConstantInt*> redirectionValues;
		unordered_map<BasicBlock*, BasicBlock*> cascadeOrigin;
		unordered_map<BasicBlock*, BasicBlock*> phiOnlyBlocks;
		
		unordered_multimap<BasicBlock*, BasicBlock*> backEdges;
		unordered_multimap<BasicBlock*, BasicBlock*> loopMembers;
		
		LoopCollapseEntries() : FunctionPass(ID)
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
			
			raw_os_ostream rerr(cerr);
			for (BasicBlock* bb : postOrder)
			{
				changed |= runOnCycle(*bb);
			}
			
			return changed;
		}
		
		virtual bool runOnCycle(BasicBlock& backEdgeDestination)
		{
			bool changed = false;
			
			// Build graph slice
			unordered_set<BasicBlock*> sinkNodeSet;
			auto range = backEdges.equal_range(&backEdgeDestination);
			for (auto iter = range.first; iter != range.second; iter++)
			{
				sinkNodeSet.insert(iter->second);
			}
			
			auto graphSlice = buildGraphSlice(&backEdgeDestination, sinkNodeSet);
			
			// Build initial loop membership set
			unordered_set<BasicBlock*> members;
			for (const auto& path : graphSlice)
			{
				members.insert(path.begin(), path.end());
			}
			
			// The graph slice algorithm won't follow back edges. Because of that, if the cycle contains a sub-cycle,
			// we need to add its member nodes. This is probably handled by the loop membership refinement step from
			// the "No More Gotos" paper, but as noted below, we don't use that step.
			unordered_set<BasicBlock*> newMembers;
			for (BasicBlock* bb : members)
			{
				auto range = loopMembers.equal_range(bb);
				for (auto iter = range.first; iter != range.second; iter++)
				{
					newMembers.insert(iter->second);
				}
			}
			members.insert(newMembers.begin(), newMembers.end());
			
			unordered_set<BasicBlock*> entries; // nodes inside the loop that are reached from the outside
			for (BasicBlock* member : members)
			{
				for (BasicBlock* pred : predecessors(member))
				{
					if (members.count(pred) == 0)
					{
						entries.insert(member);
					}
				}
			}

			// The "No More Gotos" paper suggests a step of "loop membership refinement", but it seems dubiously useful
			// to me. I could have done it wrong, but from my experience, it'll just gobble up non-looping nodes and
			// stick a break statement after them. Git commit 9b2f84f9bb5ab5348f7dc8548474442622de5114 has the last
			// revision of this file before I removed the loop membership refinement step.
			
			if (entries.size() > 1)
			{
				Function* fn = backEdgeDestination.getParent();
				auto& ctx = fn->getContext();
				
				unordered_set<BasicBlock*> enteringNodes;
				// Fix abnormal entries. We need to update entering nodes...
				for (BasicBlock* entry : entries)
				{
					for (BasicBlock* pred : predecessors(entry))
					{
						if (members.count(pred) == 0)
						{
							enteringNodes.insert(pred);
						}
					}
				}
				
				// ... and every predecessor of the back-edge destination node, in or out of the loop.
				for (BasicBlock* pred : predecessors(&backEdgeDestination))
				{
					enteringNodes.insert(pred);
				}
				
				// Introduce funnel basic block and PHI node.
				singleEntry = BasicBlock::Create(ctx, "single-entry.funnel", fn);
				intTy = Type::getInt32Ty(ctx);
				auto truncatedBlocksCount = static_cast<unsigned>(enteringNodes.size());
				phiNode = PHINode::Create(intTy, truncatedBlocksCount, "", singleEntry);
				
				// Clear object-global state.
				redirectionValues.clear();
				cascadeOrigin.clear();
				phiOnlyBlocks.clear();
				
				createFunnelBlock(members, enteringNodes);
				fixPhiNodes(entries, enteringNodes);
				
				changed = true;
			}
			
			// This pass also used to have exit normalization code, but it was removed in favor of letting
			// LoopSimplify do the heavy lifting. Git commit dfc63baaba93e883913caa07dc89633ad8d5e968 has the last
			// revision of this file before I removed exit normalization.
			
#ifdef DEBUG
			raw_os_ostream rerr(cerr);
			if (verifyFunction(*backEdgeDestination.getParent(), &rerr))
			{
				abort();
			}
#endif
			
			return changed;
		}
		
		void fixPhiNodes(const unordered_set<BasicBlock*>& entries, const unordered_set<BasicBlock*>& enteringNodes)
		{
			// Raise PHI nodes to the funnel node, when necessary.
			vector<PHINode*> insertedNodes;
			unsigned truncatedBlockCount = static_cast<unsigned>(enteringNodes.size());
			for (BasicBlock* entry : entries)
			{
				for (auto iter = entry->begin(); PHINode* phi = dyn_cast<PHINode>(iter); ++iter)
				{
					unsigned i = 0;
					PHINode* singleEntryPhi = nullptr;
					while (i < phi->getNumIncomingValues())
					{
						BasicBlock* incomingBlock = phi->getIncomingBlock(i);
						if (enteringNodes.count(incomingBlock) == 0)
						{
							++i;
						}
						else
						{
							bool addToThisPhi = false;
							if (singleEntryPhi == nullptr)
							{
								singleEntryPhi = PHINode::Create(phi->getType(), truncatedBlockCount, "", singleEntry->getFirstNonPHI());
								insertedNodes.push_back(singleEntryPhi);
								addToThisPhi = true;
							}
							
							Value* incomingValue = phi->getIncomingValue(i);
							singleEntryPhi->addIncoming(incomingValue, incomingBlock);
							if (addToThisPhi)
							{
								phi->setIncomingBlock(i, cascadeOrigin[entry]);
								phi->setIncomingValue(i, singleEntryPhi);
								++i;
							}
							else
							{
								phi->removeIncomingValue(i);
							}
						}
					}
				}
			}
			
			// Set undefined values for every case that wasn't covered.
			for (PHINode* phi : insertedNodes)
			{
				for (const auto& predPair : phiOnlyBlocks)
				{
					BasicBlock* pred = predPair.first;
					int index = phi->getBasicBlockIndex(pred);
					if (index == -1)
					{
						BasicBlock* actualPred = predPair.second;
						int actualIndex = phi->getBasicBlockIndex(actualPred);
						if (actualIndex == -1)
						{
							phi->addIncoming(UndefValue::get(phi->getType()), pred);
						}
						else
						{
							phi->addIncoming(phi->getIncomingValue(actualIndex), pred);
						}
					}
				}
			}
		}
		
		void createFunnelBlock(const unordered_set<BasicBlock*>& members, const unordered_set<BasicBlock*>& enteringBlocks)
		{
			BasicBlock* anyBB = *enteringBlocks.begin();
			Function* fn = anyBB->getParent();
			LLVMContext& ctx = anyBB->getContext();
			
			// Redirect blocks.
			for (BasicBlock* enteringBlock : enteringBlocks)
			{
				phiOnlyBlocks[enteringBlock] = enteringBlock;
				auto terminator = enteringBlock->getTerminator();
				if (auto branch = dyn_cast<BranchInst>(terminator))
				{
					fixBranchInst(members, branch);
				}
				else
				{
					assert(isa<ReturnInst>(terminator) && "implement other terminator insts");
				}
			}
			
			// Create cascading if conditions.
			BranchInst* lastBranch = nullptr;
			BasicBlock* endBlock = singleEntry;
			assert(redirectionValues.size() > 1);
			for (const auto& pair : redirectionValues)
			{
				BasicBlock* targetBlock = pair.first;
				ConstantInt* key = pair.second;
				cascadeOrigin[targetBlock] = endBlock;
				
				BasicBlock* next = BasicBlock::Create(ctx, "single-entry.funnel.cascade", fn);
				Value* comp = new ICmpInst(*endBlock, ICmpInst::ICMP_EQ, phiNode, key);
				lastBranch = BranchInst::Create(targetBlock, next, comp, endBlock);
				endBlock = next;
			}
			
			// Clean up after last created block, since it's empty.
			auto branchParent = lastBranch->getParent();
			auto lastTarget = lastBranch->getSuccessor(0);
			cascadeOrigin[lastTarget] = branchParent->getUniquePredecessor();
			branchParent->replaceAllUsesWith(lastTarget);
			branchParent->eraseFromParent();
			endBlock->eraseFromParent();
		}
		
		void fixBranchInst(const unordered_set<BasicBlock*>& members, BranchInst* branch, BasicBlock* edgeStart = nullptr)
		{
			edgeStart = edgeStart == nullptr ? branch->getParent() : edgeStart;
			if (members.count(branch->getSuccessor(0)) != 0)
			{
				fixBranchSuccessor(branch, 0, edgeStart);
				
				// Are both successors outside the loop? if so, we'll run into problems with the PHINode
				// scheme. Insert additional dummy block inside of loop.
				if (branch->isConditional())
				{
					auto falseSucc = branch->getSuccessor(1);
					if (members.count(falseSucc) != 0)
					{
						BasicBlock* phiOnlyExit = BasicBlock::Create(falseSucc->getContext(), "single-entry.dummy", falseSucc->getParent(), falseSucc);
						BranchInst* phiOnlyBranch = BranchInst::Create(falseSucc, phiOnlyExit);
						branch->setSuccessor(1, phiOnlyExit);
						phiOnlyBlocks[phiOnlyExit] = edgeStart;
						fixBranchInst(members, phiOnlyBranch, edgeStart);
					}
				}
			}
			else if (branch->isConditional() && members.count(branch->getSuccessor(1)) != 0)
			{
				fixBranchSuccessor(branch, 1, edgeStart);
			}
		}
		
		void fixBranchSuccessor(BranchInst* branch, unsigned successor, BasicBlock* edgeStart)
		{
			BasicBlock* exit = branch->getSuccessor(successor);
			auto& phiValue = redirectionValues[exit];
			if (phiValue == nullptr)
			{
				phiValue = ConstantInt::get(intTy, redirectionValues.size() - 1);
			}
			
			branch->setSuccessor(successor, singleEntry);
			phiNode->addIncoming(phiValue, branch->getParent());
		}
	};
	
	char LoopCollapseEntries::ID = 0;
}

FunctionPass* createLoopCollapseEntriesPass()
{
	return new LoopCollapseEntries;
}

INITIALIZE_PASS_BEGIN(LoopCollapseEntries, "selopp", "Turn loops with multiple entries into loops with a single entry", true, false)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_END(LoopCollapseEntries, "seloop", "Turn loops with multiple entries into loops with a single entry", true, false)
