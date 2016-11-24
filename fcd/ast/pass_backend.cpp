//
// pass_backend.cpp
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

#include "metadata.h"
#include "passes.h"
#include "pass_backend.h"
#include "pre_ast_cfg_traits.h"

#include <llvm/IR/Constants.h>
#include <llvm/ADT/DepthFirstIterator.h>
#include <llvm/ADT/PostOrderIterator.h>
#include <llvm/ADT/SCCIterator.h>
#include <llvm/Analysis/DominanceFrontierImpl.h>
#include <llvm/Analysis/LoopInfoImpl.h>
#include <llvm/Analysis/RegionInfo.h>
#include <llvm/Analysis/RegionInfoImpl.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_os_ostream.h>

#include <algorithm>
#include <deque>
#include <list>
#include <unordered_set>
#include <vector>

using namespace llvm;
using namespace std;

namespace
{
	uint64_t getVirtualAddress(FunctionNode& node)
	{
		if (auto address = md::getVirtualAddress(node.getFunction()))
		{
			return address->getLimitedValue();
		}
		return 0;
	}
	
	struct DfsStackItem
	{
		PreAstBasicBlock& block;
		typedef decltype(block.successors)::iterator block_iterator;
		block_iterator current;
		
		DfsStackItem(PreAstBasicBlock& block)
		: block(block), current(block.successors.begin())
		{
		}
		
		block_iterator end()
		{
			return block.successors.end();
		}
	};
	
	void ensureSingleEntrySingleExitCycles(PreAstContext& function)
	{
		// Ensure that "loops" (SCCs) have a single entry and a single exit.
		vector<vector<PreAstBasicBlock*>> stronglyConnectedComponents;
		for (auto iter = scc_begin(&function); iter != scc_end(&function); ++iter)
		{
			if (iter.hasLoop())
			{
				stronglyConnectedComponents.push_back(*iter);
			}
		}
		
		for (auto& scc : stronglyConnectedComponents)
		{
			SmallPtrSet<PreAstBasicBlock*, 16> sccSet(scc.begin(), scc.end());
			SmallPtrSet<PreAstBasicBlock*, 16> entryNodes;
			SmallPtrSet<PreAstBasicBlock*, 16> exitNodes;
			SmallPtrSet<PreAstBasicBlockEdge*, 16> enteringEdges;
			SmallVector<PreAstBasicBlockEdge*, 16> exitingEdges;
			for (PreAstBasicBlock* bb : scc)
			{
				for (PreAstBasicBlockEdge* edge : bb->predecessors)
				{
					if (sccSet.count(edge->from) == 0)
					{
						entryNodes.insert(edge->to);
						enteringEdges.insert(edge);
					}
				}
				for (PreAstBasicBlockEdge* edge : bb->successors)
				{
					if (sccSet.count(edge->to) == 0)
					{
						exitNodes.insert(edge->to);
						exitingEdges.push_back(edge);
					}
				}
			}
			
			// Identify back edges and add them to set of entering edges.
			deque<DfsStackItem> dfsStack;
			dfsStack.emplace_back(**entryNodes.begin());
			while (dfsStack.size() > 0)
			{
				DfsStackItem& top = dfsStack.back();
				if (top.current == top.end())
				{
					dfsStack.pop_back();
					continue;
				}
				
				PreAstBasicBlockEdge* edge = *top.current;
				++top.current;
				if (sccSet.count(edge->to) == 0)
				{
					continue;
				}
				
				auto iter = find_if(dfsStack.begin(), dfsStack.end(), [=](DfsStackItem& stackItem) {
					return &stackItem.block == edge->to;
				});
				if (iter != dfsStack.end())
				{
					entryNodes.insert(edge->to);
					enteringEdges.insert(edge);
				}
				else
				{
					dfsStack.emplace_back(*edge->to);
				}
			}
			
			if (entryNodes.size() > 1)
			{
				// Redirect entering edges to a head block.
				vector<PreAstBasicBlockEdge*> collectedEdges(enteringEdges.begin(), enteringEdges.end());
				function.createRedirectorBlock(collectedEdges);
			}
			
			if (exitNodes.size() > 1)
			{
				function.createRedirectorBlock(exitingEdges);
			}
		}
	}
	
	bool derefEqual(const Expression* a, const Expression* b)
	{
		return *a == *b;
	}
	
	class Structurizer
	{
		typedef PreAstBasicBlockRegionTraits::RegionT Region;
		typedef PreAstBasicBlockRegionTraits::RegionNodeT RegionNode;
		typedef GraphTraits<RegionNode*> GraphT;
		
		AstContext& ctx;
		PreAstContext& function;
		list<PreAstBasicBlock*> blocksInPostOrder;
		typedef decltype(blocksInPostOrder)::iterator block_iterator;
		
		Statement* foldBasicBlocks(block_iterator begin, block_iterator end)
		{
			// Fold blocks into one sequence. This is easy now that we can just iterate over the region range, which is
			// sorted in post order.
			SequenceStatement* resultSequence = ctx.sequence();
			SmallDenseMap<PreAstBasicBlock*, SmallVector<SmallVector<Expression*, 4>, 8>> reachingConditions;
			
			bool isLoop = false;
			SmallPtrSet<PreAstBasicBlock*, 16> memberBlocks;
			for (PreAstBasicBlock* bb : make_range(begin, end))
			{
				// Identify back-edges. If we find any back-edge, we know that we have to wrap this region in a loop
				// and insert break statements.
				memberBlocks.insert(bb);
				if (!isLoop)
				{
					for (auto succEdge : bb->successors)
					{
						if (memberBlocks.count(succEdge->to))
						{
							isLoop = true;
							break;
						}
					}
				}
				
				// Create reaching condition and insert block in larger sequence.
				auto result = reachingConditions.insert({bb, {}});
				assert(result.second);
				
				auto& disjunction = result.first->second;
				for (auto predEdge : bb->predecessors)
				{
					// Only consider the edge condition for non-entry blocks, since entry is unconditional even though
					// edges could technically have conditions.
					// (The entry is the only block that, when traversing the graph in reverse post-order, doesn't have
					// a condition.)
					auto iter = reachingConditions.find(predEdge->from);
					if (iter != reachingConditions.end())
					{
						if (iter->second.size() == 0)
						{
							// The parent was reached unconditionally. It has no paths instead of one path with true,
							// so just insert one path with the reaching condition (if it is not unconditonal itself).
							if (predEdge->edgeCondition != ctx.expressionForTrue())
							{
								disjunction.push_back({predEdge->edgeCondition});
							}
						}
						else
						{
							auto startIter = disjunction.insert(disjunction.end(), iter->second.begin(), iter->second.end());
							if (predEdge->edgeCondition != ctx.expressionForTrue())
							{
								for (auto appendIter = startIter; appendIter != disjunction.end(); ++appendIter)
								{
									appendIter->push_back(predEdge->edgeCondition);
								}
							}
						}
					}
				}
				
				// At the end of this, it's important that bb.blockStatement is a sequence in case that we need to
				// append a break statement to it.
				if (bb->blockStatement == nullptr || !isa<SequenceStatement>(bb->blockStatement))
				{
					auto seq = ctx.sequence();
					if (bb->blockStatement != nullptr)
					{
						seq->pushBack(bb->blockStatement);
					}
					bb->blockStatement = seq;
				}
				
				Statement* statementToInsert = bb->blockStatement;
				if (disjunction.size() > 0)
				{
					// Collect common condition prefix and suffix.
					auto orIter = disjunction.begin();
					auto commonPrefix = *orIter;
					auto commonSuffix = *orIter;
					for (++orIter; orIter != disjunction.end(); ++orIter)
					{
						auto prefixMismatch = mismatch(commonPrefix.begin(), commonPrefix.end(), orIter->begin(), orIter->end(), derefEqual);
						commonPrefix.erase(prefixMismatch.first, commonPrefix.end());
						
						auto suffixMismatch = mismatch(commonSuffix.rbegin(), commonSuffix.rend(), orIter->rbegin(), orIter->rend(), derefEqual);
						commonSuffix.erase(commonSuffix.begin(), suffixMismatch.first.base());
					}
					
					if (commonPrefix.size() == disjunction.front().size())
					{
						// Identical condition, clear commonSuffix so that we don't duplicate anything.
						commonSuffix.clear();
					}
					
					// Create OR-joined condition with condition parts after the prefix.
					SmallVector<Expression*, 4> disjunctionTerms;
					for (auto& andSequence : disjunction)
					{
						if (andSequence.size() != commonPrefix.size() + commonSuffix.size())
						{
							auto copyBegin = andSequence.begin() + commonPrefix.size();
							auto copyEnd = andSequence.end() - commonSuffix.size();
							Expression* subsequence = ctx.nary(NAryOperatorExpression::ShortCircuitAnd, copyBegin, copyEnd);
							disjunctionTerms.push_back(subsequence);
						}
					}
					
					// Nest into if statements for easy merging by the branch combining pass.
					for (Expression* term : commonPrefix)
					{
						statementToInsert = ctx.ifElse(term, statementToInsert);
					}
					for (Expression* term : commonSuffix)
					{
						statementToInsert = ctx.ifElse(term, statementToInsert);
					}
					if (disjunctionTerms.size() > 0)
					{
						Expression* disjunctionExpression = ctx.nary(NAryOperatorExpression::ShortCircuitOr, disjunctionTerms.begin(), disjunctionTerms.end());
						statementToInsert = ctx.ifElse(disjunctionExpression, statementToInsert);
					}
				}
				
				resultSequence->pushBack(statementToInsert);
			}
			
			// The top-level region can only be a loop if the loop has no successor. If it has no successor, it can't
			// have break statements.
			if (isLoop)
			{
				if (end != blocksInPostOrder.end())
				{
					for (PreAstBasicBlockEdge* exitingEdge : (*end)->predecessors)
					{
						PreAstBasicBlock& predecessor = *exitingEdge->from;
						if (memberBlocks.count(&predecessor) > 0)
						{
							Statement* conditionalBreak = ctx.breakStatement(exitingEdge->edgeCondition);
							cast<SequenceStatement>(predecessor.blockStatement)->pushBack(conditionalBreak);
						}
					}
				}
				return ctx.loop(ctx.expressionForTrue(), LoopStatement::PreTested, resultSequence);
			}
			else
			{
				return resultSequence;
			}
		}
		
		Statement* reduceRegion(Region& topRegion, block_iterator regionBegin, block_iterator regionEnd)
		{
			while (topRegion.begin() != topRegion.end())
			{
				Region* child = (*topRegion.begin()).get();
				PreAstBasicBlock& entry = *child->getEntry();
				PreAstBasicBlock& exit = *child->getExit();
				
				// Identify block range for this region.
				PreAstBasicBlock& newBlock = function.createBlock();
				bool foundBegin = false;
				bool foundEnd = false;
				block_iterator subregionBegin = regionEnd;
				block_iterator subregionEnd = regionEnd;
				for (auto iter = regionBegin; iter != regionEnd; ++iter)
				{
					if (*iter == &entry)
					{
						foundBegin = true;
						subregionBegin = iter;
					}
					if (*iter == &exit)
					{
						foundEnd = true;
						subregionEnd = iter;
						break;
					}
				}
				
				assert(foundBegin);
				if (!foundEnd)
				{
					// This can't read out of bounds, since only the top-level region ends at the end of the block list.
					assert(*subregionEnd == &exit);
					subregionEnd = regionEnd;
				}
				
				// Reduce region, replace block range with single new block that represents entire region. Adjust begin
				// iterator if necessary.
				bool replaceRegionBegin = regionBegin == subregionBegin;
				newBlock.blockStatement = reduceRegion(*child, subregionBegin, subregionEnd);
				auto insertIter = blocksInPostOrder.insert(subregionEnd, &newBlock);
				blocksInPostOrder.erase(subregionBegin, insertIter);
				if (replaceRegionBegin)
				{
					regionBegin = insertIter;
				}
				
				// Fix edges going into and out from the new region.
				for (PreAstBasicBlockEdge* incomingEdge : entry.predecessors)
				{
					incomingEdge->to = &newBlock;
					newBlock.predecessors.push_back(incomingEdge);
				}
				entry.predecessors.clear(); // (for good measure)
				
				// Merge outgoing edges to the same block into one single edge with 'true' as the condition.
				auto predIter = exit.predecessors.begin();
				while (predIter != exit.predecessors.end())
				{
					if (child->contains((*predIter)->from))
					{
						predIter = exit.predecessors.erase(predIter);
					}
					else
					{
						++predIter;
					}
				}
				auto& newExitEdge = function.createEdge(newBlock, exit, *ctx.expressionForTrue());
				exit.predecessors.push_back(&newExitEdge);
				newBlock.successors.push_back(&newExitEdge);
				
				topRegion.removeSubRegion(child);
			}
			
			return foldBasicBlocks(regionBegin, regionEnd);
		}
		
	public:
		Structurizer(AstContext& ctx, PreAstContext& function)
		: ctx(ctx), function(function)
		{
		}
		
		Statement* structurizeFunction(PreAstBasicBlockRegionTraits::RegionT& topRegion)
		{
			blocksInPostOrder.clear();
			for (PreAstBasicBlock* block : post_order(&function))
			{
				blocksInPostOrder.push_front(block);
			}
			
			return reduceRegion(topRegion, blocksInPostOrder.begin(), blocksInPostOrder.end());
		}
	};
}

#pragma mark - AST Pass
char AstBackEnd::ID = 0;
static RegisterPass<AstBackEnd> astBackEnd("#ast-backend", "Produce AST from LLVM module");

void AstBackEnd::getAnalysisUsage(llvm::AnalysisUsage &au) const
{
	au.setPreservesAll();
}

void AstBackEnd::addPass(AstModulePass *pass)
{
	assert(pass != nullptr);
	passes.emplace_back(pass);
}

bool AstBackEnd::runOnModule(llvm::Module &m)
{
	outputNodes.clear();
	
	for (Function& fn : m)
	{
		outputNodes.emplace_back(new FunctionNode(fn));
		output = outputNodes.back().get();
		if (!md::isPrototype(fn))
		{
			runOnFunction(fn);
		}
	}
	
	// sort outputNodes by virtual address, then by name
	sort(outputNodes.begin(), outputNodes.end(), [](unique_ptr<FunctionNode>& a, unique_ptr<FunctionNode>& b)
	{
		auto virtA = getVirtualAddress(*a);
		auto virtB = getVirtualAddress(*b);
		if (virtA < virtB)
		{
			return true;
		}
		else if (virtA == virtB)
		{
			return a->getFunction().getName() < b->getFunction().getName();
		}
		else
		{
			return false;
		}
	});
	
	// run passes
	for (auto& pass : passes)
	{
		pass->run(outputNodes);
	}
	
	return false;
}

void AstBackEnd::runOnFunction(Function& fn)
{
	// Create AST block graph.
	outputNodes.emplace_back(new FunctionNode(fn));
	FunctionNode& result = *outputNodes.back();
	blockGraph.reset(new PreAstContext(result.getContext()));
	blockGraph->generateBlocks(fn);
	
	// Ensure that blocks all have a single entry and a single exit.
	ensureSingleEntrySingleExitCycles(*blockGraph);
	
	// Compute regions.
	PreAstBasicBlockRegionTraits::DomTreeT domTree(false);
	PreAstBasicBlockRegionTraits::PostDomTreeT postDomTree(true);
	PreAstBasicBlockRegionTraits::DomFrontierT dominanceFrontier;
	PreAstBasicBlockRegionTraits::RegionInfoT regionInfo;
	domTree.recalculate(*blockGraph);
	postDomTree.recalculate(*blockGraph);
	dominanceFrontier.analyze(domTree);
	regionInfo.recalculate(*blockGraph, &domTree, &postDomTree, &dominanceFrontier);
	
	// Iterate regions in post-order. Since regions don't capture block ownership (and iterating region nodes in
	// post-order crashes in LLVM 3.9), we iterate in basic block post-order and try to match regions with blocks.
	PreAstBasicBlockRegionTraits::RegionT* rootNode = regionInfo.getTopLevelRegion();
	auto body = Structurizer(result.getContext(), *blockGraph).structurizeFunction(*rootNode);
	result.setBody(body);
}

INITIALIZE_PASS_BEGIN(AstBackEnd, "astbe", "AST Back-End", true, false)
INITIALIZE_PASS_END(AstBackEnd, "astbe", "AST Back-End", true, false)

AstBackEnd* createAstBackEnd()
{
	return new AstBackEnd;
}
