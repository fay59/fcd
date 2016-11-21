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

#include "pass_backend.h"
#include "metadata.h"
#include "passes.h"
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
#include <llvm/Support/GraphWriter.h>
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
	
	// BUG: A loop with a nested loop shows as a single SCC.
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
		
		// Given that this happens in post-order, I *think* that we don't need to check again after modifying SCCs?
		// (Famous last words.)
		for (auto& scc : stronglyConnectedComponents)
		{
			SmallPtrSet<PreAstBasicBlock*, 16> sccSet(scc.begin(), scc.end());
			SmallPtrSet<PreAstBasicBlock*, 16> entryNodes;
			SmallPtrSet<PreAstBasicBlock*, 16> exitNodes;
			SmallVector<PreAstBasicBlockEdge*, 16> enteringEdges;
			SmallVector<PreAstBasicBlockEdge*, 16> exitingEdges;
			for (PreAstBasicBlock* bb : scc)
			{
				for (PreAstBasicBlockEdge* edge : bb->predecessors)
				{
					if (sccSet.count(edge->from) == 0)
					{
						entryNodes.insert(edge->to);
						enteringEdges.push_back(edge);
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
			
			if (entryNodes.size() > 1)
			{
				// Add every edge to an entry block to the entering edges.
				SmallPtrSet<PreAstBasicBlock*, 16> entryBlocks;
				for (PreAstBasicBlockEdge* enteringEdge : enteringEdges)
				{
					entryBlocks.insert(enteringEdge->to);
				}
				
				SmallPtrSet<PreAstBasicBlockEdge*, 16> enteringEdgesSet(enteringEdges.begin(), enteringEdges.end());
				for (PreAstBasicBlock* entryBlock : entryBlocks)
				{
					for (PreAstBasicBlockEdge* pred : entryBlock->predecessors)
					{
						enteringEdgesSet.insert(pred);
					}
				}
				
				// Redirect entering edges to a head block.
				vector<PreAstBasicBlockEdge*> collectedEdges(enteringEdgesSet.begin(), enteringEdgesSet.end());
				function.createRedirectorBlock(collectedEdges);
			}
			
			if (exitNodes.size() > 1)
			{
				function.createRedirectorBlock(exitingEdges);
			}
		}
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
		
		SequenceStatement* reduceRegion(Region& topRegion, block_iterator regionBegin, block_iterator regionEnd)
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
				assert(foundBegin && foundEnd);
				
				// Reduce region, replace block range with single new block that represents entire region. Adjust begin
				// iterator if necessary.
				newBlock.blockStatement = reduceRegion(*child, subregionBegin, subregionEnd);
				auto insertIter = blocksInPostOrder.insert(subregionEnd, &newBlock);
				if (*subregionBegin == &entry)
				{
					regionBegin = insertIter;
				}
				blocksInPostOrder.erase(subregionBegin, insertIter);
				
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
			
			// Fold blocks into one sequence. This is easy now that we can just iterate over the region range, which is
			// sorted in post order.
			SequenceStatement* resultSequence = ctx.sequence();
			SmallDenseMap<PreAstBasicBlock*, Expression*> reachingConditions;
			for (auto regionIter = regionBegin; regionIter != regionEnd; ++regionIter)
			{
				PreAstBasicBlock& bb = **regionIter;
				Expression* disjunctReachingCondition = nullptr;
				for (auto predEdge : bb.predecessors)
				{
					Expression* reachingCondition = predEdge->edgeCondition;
					auto iter = reachingConditions.find(predEdge->from);
					if (iter != reachingConditions.end())
					{
						reachingCondition = ctx.nary(NAryOperatorExpression::ShortCircuitAnd, iter->second, reachingCondition);
					}
					disjunctReachingCondition = disjunctReachingCondition == nullptr
						? reachingCondition
						: ctx.nary(NAryOperatorExpression::ShortCircuitOr, disjunctReachingCondition, reachingCondition);
				}
				
				if (disjunctReachingCondition == nullptr)
				{
					if (bb.blockStatement != nullptr)
					{
						resultSequence->pushBack(bb.blockStatement);
					}
				}
				else
				{
					auto result = reachingConditions.insert({&bb, disjunctReachingCondition});
					assert(result.second); (void) result;
					
					// Some blocks only exist to provide edges for reaching condition and don't have a body, ignore
					// these.
					if (bb.blockStatement != nullptr)
					{
						resultSequence->pushBack(ctx.ifElse(disjunctReachingCondition, bb.blockStatement));
					}
				}
			}
			return resultSequence;
		}
		
	public:
		Structurizer(AstContext& ctx, PreAstContext& function)
		: ctx(ctx), function(function)
		{
		}
		
		Statement* structurizeFunction(PreAstBasicBlockRegionTraits::RegionT& topRegion)
		{
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

void AstBackEnd::runOnFunction(llvm::Function& fn)
{
	// Create AST block graph.
	outputNodes.emplace_back(new FunctionNode(fn));
	FunctionNode& result = *outputNodes.back();
	blockGraph.reset(new PreAstContext(result.getContext()));
	blockGraph->generateBlocks(fn);
	
	// Ensure that blocks all have a single entry and a single exit.
	// (BUG: this doesn't work.)
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
