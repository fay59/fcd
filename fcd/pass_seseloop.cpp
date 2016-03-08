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
#include "metadata.h"
#include "passes.h"
#include "pass_seseloop.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/PostOrderIterator.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Transforms/Utils/SSAUpdater.h>
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
	
	void fixNonDominatingValues(DominatorTree& domTree, iterator_range<SmallVectorImpl<BasicBlock*>::iterator> range)
	{
		if (range.begin() == range.end())
		{
			return;
		}
		
		SSAUpdater updater;
		BasicBlock* modifiedBlock = *range.begin();
		BasicBlock* entryBlock = &modifiedBlock->getParent()->getEntryBlock();
		for (BasicBlock* noLongerDominating : range)
		{
			// This part is basically the same as StructurizeCFG's rebuildSSA.
			// raw iterators since use list is modified below
			for (auto iter = noLongerDominating->begin(); iter != noLongerDominating->end(); ++iter)
			{
				bool initialized = false;
				auto useIter = iter->use_begin();
				while (useIter != iter->use_end())
				{
					Use& use = *useIter;
					++useIter;
					
					Instruction* user = cast<Instruction>(use.getUser());
					BasicBlock* userBlock = user->getParent();
					
					if (userBlock == noLongerDominating)
					{
						continue;
					}
					else if (auto phi = dyn_cast<PHINode>(user))
					{
						if (phi->getIncomingBlock(use) == noLongerDominating)
						{
							continue;
						}
					}
					else if (!domTree.dominates(modifiedBlock, userBlock))
					{
						continue;
					}
					
					if (!initialized)
					{
						Type* type = use->getType();
						updater.Initialize(type, "");
						updater.AddAvailableValue(entryBlock, UndefValue::get(type));
						updater.AddAvailableValue(noLongerDominating, &*iter);
						initialized = true;
					}
					updater.RewriteUseAfterInsertions(use);
				}
			}
		}
	}
	
	BasicBlock* createFunnelBlock(DominatorTree& domTree, const unordered_set<BasicBlock*>& members, const unordered_set<BasicBlock*>& frontierBlocks, bool fixMembers)
	{
		BasicBlock* anyBB = *frontierBlocks.begin();
		Function* fn = anyBB->getParent();
		LLVMContext& ctx = anyBB->getContext();
		
		// Introduce funnel basic block and PHI node. The PHI node's purpose is to direct execution to one of
		// enteringBlock.
		Type* i32 = Type::getInt32Ty(ctx);
		BasicBlock* funnel = BasicBlock::Create(ctx, "sese.funnel", fn);
		PHINode* predSwitchNode = PHINode::Create(i32, static_cast<unsigned>(frontierBlocks.size()), "", funnel);
		
		// Create a cascade of blocks branching to enteringBlocks.
		unordered_map<BasicBlock*, BasicBlock*> predMap;
		BasicBlock* previousCascade = nullptr;
		BasicBlock* currentCascade = funnel;
		uint32_t counter = 0;
		for (BasicBlock* thisBlock : frontierBlocks)
		{
			previousCascade = currentCascade;
			currentCascade = BasicBlock::Create(ctx, "sese.funnel.cascade", fn);
			auto constantI = ConstantInt::get(i32, counter++);

			// raw iterators as use list is modified below
			SmallPtrSet<BasicBlock*, 4> updatedPredecessors;
			auto useIter = thisBlock->use_begin();
			while (useIter != thisBlock->use_end())
			{
				Use& blockUse = *useIter;
				++useIter;
				if (auto branch = dyn_cast<BranchInst>(blockUse.getUser()))
				{
					BasicBlock* pred = branch->getParent();
					predMap[pred] = pred;
					if (fixMembers || members.count(pred) != 0)
					{
						int index = predSwitchNode->getBasicBlockIndex(pred);
						if (index == -1)
						{
							// modifies the use list
							blockUse.set(funnel);
							predSwitchNode->addIncoming(constantI, pred);
						}
						else
						{
							// the other branch already points to the funnel, we'll need a dummy block
							auto dummy = BasicBlock::Create(ctx, "sese.funnel.dummy", fn);
							BranchInst::Create(funnel, dummy);
							blockUse.set(dummy);
							predSwitchNode->addIncoming(constantI, dummy);
							predMap[dummy] = pred;
						}
						updatedPredecessors.insert(pred);
					}
				}
			}
			
			auto cmp = ICmpInst::Create(ICmpInst::ICmp, ICmpInst::ICMP_EQ, predSwitchNode, constantI, "", previousCascade);
			BranchInst::Create(thisBlock, currentCascade, cmp, previousCascade);
			
			if (updatedPredecessors.size() > 0)
			{
				// Create a PHI node in the funnel with the incoming values for the blocks that are
				// directed to the funnel. Add an incoming value for the funnel from this PHI node.
				unsigned nodeNumber = 0;
				for (auto iter = thisBlock->begin(); auto phi = dyn_cast<PHINode>(iter); ++iter, ++nodeNumber)
				{
					Twine name = thisBlock->getName() + "." + to_string(nodeNumber);
					auto raisedPhi = PHINode::Create(phi->getType(), phi->getNumIncomingValues(), name);
					for (unsigned i = phi->getNumIncomingValues(); i > 0; --i)
					{
						unsigned index = i - 1;
						BasicBlock* incomingBlock = phi->getIncomingBlock(index);
						if (updatedPredecessors.count(incomingBlock) != 0)
						{
							raisedPhi->addIncoming(phi->getIncomingValue(index), incomingBlock);
							phi->removeIncomingValue(index, false);
						}
					}
					
					if (raisedPhi->getNumIncomingValues() != 0)
					{
						raisedPhi->insertBefore(predSwitchNode);
						phi->addIncoming(raisedPhi, previousCascade);
					}
					else
					{
						// uncommon case where nothing had to be moved around
						delete raisedPhi;
					}
				}
			}
		}
		
		// Fix PHI nodes in the funnel
		SmallVector<BasicBlock*, 10> preds(pred_begin(funnel), pred_end(funnel));
		for (auto iter = funnel->begin(); auto phi = dyn_cast<PHINode>(iter); ++iter)
		{
			for (BasicBlock* pred : preds)
			{
				if (phi->getBasicBlockIndex(pred) == -1)
				{
					int synonym = phi->getBasicBlockIndex(predMap[pred]);
					if (synonym == -1)
					{
						Type* type = phi->getType();
						phi->addIncoming(UndefValue::get(type), pred);
					}
					else
					{
						phi->addIncoming(phi->getIncomingValue((uint32_t)synonym), pred);
					}
				}
			}
		}
		
		// Fix last branch the cheap way.
		// (Leaves a branch-only BB behind but we can live with that)
		BasicBlock* lastBB = cast<BranchInst>(previousCascade->getTerminator())->getSuccessor(0);
		BasicBlock* branchOnlyBB = BasicBlock::Create(ctx, "sese.funnel.final", fn);
		BranchInst::Create(lastBB, branchOnlyBB);
		previousCascade->replaceAllUsesWith(branchOnlyBB);
		previousCascade->eraseFromParent();
		currentCascade->eraseFromParent();
		
		// Lastly, fix values that are no longer dominating. For each frontier block, we want to find out
		// which blocks that dominated it before are no longer dominating.
		unordered_map<BasicBlock*, SmallVector<BasicBlock*, 8>> dominatingBeforeTransform;
		for (BasicBlock* frontierBlock : frontierBlocks)
		{
			auto& dominators = dominatingBeforeTransform[frontierBlock];
			for (auto node = domTree.getNode(frontierBlock); node != nullptr; node = node->getIDom())
			{
				dominators.push_back(node->getBlock());
			}
		}
		
		domTree.recalculate(*fn);
		for (BasicBlock* frontierBlock : frontierBlocks)
		{
			SmallVector<BasicBlock*, 8> newDominators;
			for (auto node = domTree.getNode(frontierBlock); node != nullptr; node = node->getIDom())
			{
				newDominators.push_back(node->getBlock());
			}
			
			auto& oldDominators = dominatingBeforeTransform[frontierBlock];
			auto firstChangePair = mismatch(newDominators.rbegin(), newDominators.rend(), oldDominators.rbegin());
			auto firstCommonInOldList = firstChangePair.second.base();
			fixNonDominatingValues(domTree, make_range(oldDominators.begin(), firstCommonInOldList));
		}
		
		return funnel;
	}
}

char SESELoop::ID = 0;

unordered_multimap<BasicBlock*, BasicBlock*> SESELoop::findBackEdgeDestinations(BasicBlock& entryPoint)
{
	unordered_set<BasicBlock*> visited;
	unordered_multimap<BasicBlock*, BasicBlock*> result;
	deque<BasicBlock*> visitedStack;
	::findBackEdgeDestinations(&entryPoint, visitedStack, result, visited);
	return result;
}

void SESELoop::getAnalysisUsage(AnalysisUsage& au) const
{
	au.addRequired<DominatorTreeWrapperPass>();
}

bool SESELoop::runOnFunction(Function& fn)
{
	if (md::isPrototype(fn))
	{
		return false;
	}
	
	loopMembers.clear();
	bool changed = false;
	bool changedThisIteration;
	do
	{
		changedThisIteration = false;
		unordered_multimap<BasicBlock*, BasicBlock*> destToOrigin = findBackEdgeDestinations(fn.getEntryBlock());
		
		vector<BasicBlock*> postOrderBackwardsEdges;
		for (BasicBlock* bb : post_order(&fn.getEntryBlock()))
		{
			if (destToOrigin.count(bb) != 0)
			{
				postOrderBackwardsEdges.push_back(bb);
			}
		}
		
		for (BasicBlock* bb : postOrderBackwardsEdges)
		{
			if (runOnBackgoingBlock(*bb, destToOrigin))
			{
				changed = true;
				changedThisIteration = true;
				break;
			}
		}
	} while (changedThisIteration);
	
	return changed;
}

void SESELoop::buildLoopMemberSet(BasicBlock& backEdgeDestination, const unordered_multimap<BasicBlock*, BasicBlock*>& destToOrigin, unordered_set<BasicBlock*>& members, unordered_set<BasicBlock*>& entries, unordered_set<BasicBlock*>& exits)
{
	// Build paths to back-edge start nodes.
	unordered_set<BasicBlock*> sinkNodeSet;
	auto range = destToOrigin.equal_range(&backEdgeDestination);
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
}

bool SESELoop::runOnBackgoingBlock(BasicBlock& backEdgeDestination, const unordered_multimap<BasicBlock*, BasicBlock*>& backEdgeMap)
{
	unordered_set<BasicBlock*> members;
	unordered_set<BasicBlock*> entries; // nodes inside the loop that are reached from the outside
	unordered_set<BasicBlock*> exits; // nodes outside the loop that are preceded by a node inside of it
	buildLoopMemberSet(backEdgeDestination, backEdgeMap, members, entries, exits);

	// The "No More Gotos" paper suggests a step of "loop membership refinement", but it seems dubiously useful
	// to me. I could have done it wrong, but from my experience, it'll just gobble up non-looping nodes and
	// stick a break statement after them. Git commit 9b2f84f9bb5ab5348f7dc8548474442622de5114 has the last
	// revision of this file before I removed the loop membership refinement step.
	
	bool changed = false;
	auto& domTree = getAnalysis<DominatorTreeWrapperPass>().getDomTree();
	if (entries.size() > 1)
	{
		BasicBlock* funnel = createFunnelBlock(domTree, members, entries, true);
		assert(verifyFunction(*backEdgeDestination.getParent(), &errs()) == 0);
		members.insert(funnel);
		changed = true;
	}
	
	if (exits.size() > 1)
	{
		createFunnelBlock(domTree, members, exits, false);
		assert(verifyFunction(*backEdgeDestination.getParent(), &errs()) == 0);
		changed = true;
	}
	
	return changed;
}

FunctionPass* createSESELoopPass()
{
	return new SESELoop;
}

INITIALIZE_PASS(SESELoop, "seseloop", "Turn loops with multiple entries into loops with a single entry", true, false)
