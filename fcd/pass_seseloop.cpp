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

#include "llvm_warnings.h"
#include "passes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/PostOrderIterator.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <deque>
#include <unordered_map>
#include <unordered_set>

using namespace llvm;
using namespace std;

template<typename TColl>
void dump(const TColl& coll)
{
	raw_ostream& os = errs();
	for (BasicBlock* bb : coll)
	{
		bb->printAsOperand(os);
		os << '\n';
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
	void findPathsToSinkNodes(TGraphType currentNode, const unordered_set<TGraphType>& sinkNodes, vector<vector<TGraphType>>& results, deque<TGraphType>& stack)
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
				findPathsToSinkNodes(explored, sinkNodes, results, stack);
			}
		}
		stack.pop_back();
	}
	
	template<typename TGraphType, typename GraphTr = GraphTraits<TGraphType>>
	vector<vector<TGraphType>> findPathsToSinkNodes(TGraphType startNode, const unordered_set<TGraphType>& sinkNodes)
	{
		vector<vector<TGraphType>> result;
		deque<TGraphType> stack;
		findPathsToSinkNodes(startNode, sinkNodes, result, stack);
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
	
	BasicBlock* findNearestCommonDominator(DominatorTree& domTree, const unordered_set<BasicBlock*>& predecessors)
	{
		auto iter = predecessors.begin();
		auto end = predecessors.end();
		assert(iter != end);
		
		BasicBlock* ncd = *iter;
		++iter;
		while (iter != end)
		{
			ncd = domTree.findNearestCommonDominator(ncd, *iter);
			if (ncd == nullptr)
			{
				assert(false);
				break;
			}
			++iter;
		}
		return ncd;
	}
	
	inline bool isMember(const unordered_set<BasicBlock*> members, BasicBlock* bb)
	{
		return members.count(bb) != 0;
	}
	
	struct SESELoop : public FunctionPass
	{
		static char ID;
		
		BasicBlock* funnel;
		IntegerType* intTy;
		PHINode* phiNode;
		unordered_map<BasicBlock*, ConstantInt*> redirectionValues;
		unordered_map<BasicBlock*, BasicBlock*> cascadeOrigin;
		unordered_map<BasicBlock*, BasicBlock*> phiEquivalent;
		
		unordered_multimap<BasicBlock*, BasicBlock*> backwardsDestinationToStart;
		unordered_multimap<BasicBlock*, BasicBlock*> loopMembers;
		
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
			backwardsDestinationToStart = findBackEdgeDestinations(fn.getEntryBlock());
			
			vector<BasicBlock*> postOrderBackwardsEdges;
			for (BasicBlock* bb : post_order(&fn.getEntryBlock()))
			{
				if (backwardsDestinationToStart.count(bb) != 0)
				{
					postOrderBackwardsEdges.push_back(bb);
				}
			}
			
			for (BasicBlock* bb : postOrderBackwardsEdges)
			{
				changed |= runOnBackgoingBlock(*bb);
			}
			
			return changed;
		}
		
		unordered_set<BasicBlock*> buildLoopMemberSet(BasicBlock& backEdgeDestination)
		{
			unordered_set<BasicBlock*> members;
			
			// Build paths to back-edge start nodes.
			unordered_set<BasicBlock*> sinkNodeSet;
			auto range = backwardsDestinationToStart.equal_range(&backEdgeDestination);
			for (auto iter = range.first; iter != range.second; iter++)
			{
				sinkNodeSet.insert(iter->second);
			}
			
			auto pathsToBackNodes = findPathsToSinkNodes(&backEdgeDestination, sinkNodeSet);
			
			// Build initial loop membership set
			for (const auto& path : pathsToBackNodes)
			{
				members.insert(path.begin(), path.end());
			}
			
			// The path-to-sink-nodes algorithm won't follow back edges. Because of that, if the cycle contains a
			// sub-cycle, we need to add its member nodes. This is probably handled by the loop membership refinement
			// step from the "No More Gotos" paper, but as noted below, we don't use that step.
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
			return members;
		}
		
		bool runOnBackgoingBlock(BasicBlock& backEdgeDestination)
		{
			bool changed = false;
			
			unordered_set<BasicBlock*> members = buildLoopMemberSet(backEdgeDestination);
			unordered_set<BasicBlock*> entries; // nodes inside the loop that are reached from the outside
			unordered_set<BasicBlock*> exits; // nodes outside the loop that are preceded by a node inside of it
			for (BasicBlock* member : members)
			{
				loopMembers.insert({&backEdgeDestination, member});
				
				for (BasicBlock* pred : predecessors(member))
				{
					if (members.count(pred) == 0)
					{
						entries.insert(member);
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
				
				createFunnelBlock(members, enteringNodes, false);
				fixPhiNodes(entries, enteringNodes);
				members.insert(funnel);
				
#ifdef DEBUG
				if (verifyFunction(*backEdgeDestination.getParent(), &errs()))
				{
					abort();
				}
#endif
				
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
				createFunnelBlock(members, exitPreds, true);
				fixPhiNodes(exits, exitPreds);
				fixNonDominatingValues(exitPreds);
				
#ifdef DEBUG
				if (verifyFunction(*backEdgeDestination.getParent(), &errs()))
				{
					abort();
				}
#endif
				
				changed = true;
			}
			
			return changed;
		}
		
		void createFunnelBlock(const unordered_set<BasicBlock*>& members, const unordered_set<BasicBlock*>& enteringBlocks, bool fixIfMember)
		{
			BasicBlock* anyBB = *enteringBlocks.begin();
			Function* fn = anyBB->getParent();
			LLVMContext& ctx = anyBB->getContext();
			
			// Introduce funnel basic block and PHI node.
			funnel = BasicBlock::Create(ctx, "sese.funnel", fn);
			intTy = Type::getInt32Ty(ctx);
			auto truncatedBlocksCount = static_cast<unsigned>(enteringBlocks.size());
			phiNode = PHINode::Create(intTy, truncatedBlocksCount, "", funnel);
			
			// Clear object-global state.
			redirectionValues.clear();
			cascadeOrigin.clear();
			phiEquivalent.clear();
			
			// Redirect blocks.
			for (BasicBlock* enteringBlock : enteringBlocks)
			{
				phiEquivalent[enteringBlock] = enteringBlock;
				auto terminator = enteringBlock->getTerminator();
				if (auto branch = dyn_cast<BranchInst>(terminator))
				{
					fixBranchInst(members, enteringBlock, branch, fixIfMember);
				}
				else
				{
					assert(isa<ReturnInst>(terminator) && "implement other terminator insts");
				}
			}
			
			// Create cascading if conditions.
			BranchInst* lastBranch = nullptr;
			BasicBlock* endBlock = funnel;
			assert(redirectionValues.size() > 1);
			for (const auto& pair : redirectionValues)
			{
				BasicBlock* targetBlock = pair.first;
				ConstantInt* key = pair.second;
				cascadeOrigin[targetBlock] = endBlock;
				
				BasicBlock* next = BasicBlock::Create(ctx, "sese.funnel.cascade", fn);
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
		
		void fixBranchInst(const unordered_set<BasicBlock*>& members, BasicBlock* edgeStart, BranchInst* branch, bool fixIfMember)
		{
			if (isMember(members, branch->getSuccessor(0)) != fixIfMember)
			{
				fixBranchSuccessor(branch, 0, edgeStart);
				
				// Are both successors outside the loop? if so, we'll run into problems with the PHINode
				// scheme. Insert additional dummy block inside of loop.
				if (branch->isConditional())
				{
					auto falseSucc = branch->getSuccessor(1);
					if (isMember(members, falseSucc) != fixIfMember)
					{
						BasicBlock* phiOnlyExit = BasicBlock::Create(falseSucc->getContext(), "sese.dummy", falseSucc->getParent(), falseSucc);
						BranchInst* phiOnlyBranch = BranchInst::Create(falseSucc, phiOnlyExit);
						branch->setSuccessor(1, phiOnlyExit);
						phiEquivalent[phiOnlyExit] = edgeStart;
						fixBranchInst(members, edgeStart, phiOnlyBranch, fixIfMember);
					}
				}
			}
			else if (branch->isConditional() && isMember(members, branch->getSuccessor(1)) != fixIfMember)
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
			
			branch->setSuccessor(successor, funnel);
			phiNode->addIncoming(phiValue, branch->getParent());
		}
		
		void fixPhiNodes(const unordered_set<BasicBlock*>& modifiedBlocks, const unordered_set<BasicBlock*>& predecessors)
		{
			// Raise PHI nodes to the funnel node, when necessary.
			vector<PHINode*> insertedNodes;
			unsigned blockCount = static_cast<unsigned>(predecessors.size());
			for (BasicBlock* modifiedBlock : modifiedBlocks)
			{
				for (auto iter = modifiedBlock->begin(); PHINode* phi = dyn_cast<PHINode>(iter); ++iter)
				{
					unsigned i = 0;
					PHINode* singleEntryPhi = nullptr;
					while (i < phi->getNumIncomingValues())
					{
						BasicBlock* incomingBlock = phi->getIncomingBlock(i);
						if (predecessors.count(incomingBlock) == 0)
						{
							++i;
						}
						else
						{
							bool addToThisPhi = false;
							if (singleEntryPhi == nullptr)
							{
								singleEntryPhi = PHINode::Create(phi->getType(), blockCount, "", funnel->getFirstNonPHI());
								insertedNodes.push_back(singleEntryPhi);
								addToThisPhi = true;
							}
							
							Value* incomingValue = phi->getIncomingValue(i);
							singleEntryPhi->addIncoming(incomingValue, incomingBlock);
							if (addToThisPhi)
							{
								phi->setIncomingBlock(i, cascadeOrigin[modifiedBlock]);
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
				for (const auto& predPair : phiEquivalent)
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
		
		void fixNonDominatingValues(const unordered_set<BasicBlock*>& predecessors)
		{
			DominatorTree domTree;
			domTree.recalculate(*(*predecessors.begin())->getParent());
			
			// Find nearest common dominator for exiting nodes, then compute the graph slice to the exit blocks.
			BasicBlock* ncd = findNearestCommonDominator(domTree, predecessors);
			auto graphSlice = findPathsToSinkNodes(ncd, predecessors);
			unordered_set<BasicBlock*> blocksToCheck;
			for (const auto& path : graphSlice)
			{
				blocksToCheck.insert(path.begin(), path.end());
			}
			
			// The nearest common dominator of the predecessors necessarily dominates the funnel block,
			// no need to check it.
			blocksToCheck.erase(ncd);
			
			// Check these blocks to make sure that each of their instructions dominate all of their uses. If not,
			// introduce PHI nodes in the funnel node.
			SmallVector<Use*, 8> uses;
			for (BasicBlock* bb : blocksToCheck)
			{
				for (Instruction& inst : *bb)
				{
					PHINode* phi = nullptr;
					
					// Collect uses into vector to avoid modifying the collection as we iterate through it.
					uses.clear();
					for (Use& use : inst.uses())
					{
						uses.push_back(&use);
					}
					
					for (Use* use : uses)
					{
						if (!domTree.dominates(&inst, *use))
						{
							createPHINodeIfNecessary(phi, domTree, inst, predecessors);
							use->set(phi);
						}
					}
				}
			}
		}
		
		void createPHINodeIfNecessary(PHINode*& phi, DominatorTree& domTree, Instruction& inst, unordered_set<BasicBlock*> predecessors)
		{
			if (phi != nullptr)
			{
				return;
			}
			
			Type* type = inst.getType();
			auto undef = UndefValue::get(type);
			phi = PHINode::Create(type, inst.getNumUses(), "", funnel->getFirstNonPHI());
			for (BasicBlock* pred : predecessors)
			{
				Value* incomingValue = inst.getParent() == pred || domTree.dominates(&inst, pred)
					? static_cast<Value*>(&inst)
					: static_cast<Value*>(undef);
				phi->addIncoming(incomingValue, pred);
			}
		}
	};
	
	char SESELoop::ID = 0;
}

FunctionPass* createSESELoopPass()
{
	return new SESELoop;
}

INITIALIZE_PASS(SESELoop, "seseloop", "Turn loops with multiple entries into loops with a single entry", true, false)
