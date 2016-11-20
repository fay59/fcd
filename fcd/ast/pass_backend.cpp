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
#include <llvm/IR/Instructions.h>
#include <llvm/Support/GraphWriter.h>
#include <llvm/Support/raw_os_ostream.h>

#include <algorithm>
#include <deque>
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
		for (auto& scc : make_range(scc_begin(&function), scc_end(&function)))
		{
			stronglyConnectedComponents.push_back(scc);
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
		unordered_set<RegionNode*> loopExits;
		unsigned loopDepth;
		
	public:
		Structurizer(AstContext& ctx)
		: ctx(ctx), loopDepth(0)
		{
		}
		
		Statement* structurizeRegion(PreAstBasicBlockRegionTraits::RegionNodeT& regionNode)
		{
			// Global sequence that has everything in it.
			SequenceStatement* seq = ctx.sequence();
			
			// RegionNodes don't implement inverse graph traits, so cache who's the predecessor of whom.
			unordered_multimap<RegionNode*, RegionNode*> predecessors;
			unordered_map<RegionNode*, Expression*> reachingConditions;
			
			for (RegionNode* subregion : ReversePostOrderTraversal<RegionNode*>(&regionNode))
			{
				PreAstBasicBlock* regionEntry = subregion->getEntry();
				
				// Insert predecessor entries.
				for (RegionNode* successor : make_range(GraphT::child_begin(subregion), GraphT::child_end(subregion)))
				{
					predecessors.insert({successor, subregion});
				}
				
				// Compute reaching condition as the disjunction of every predecessor's reaching condition.
				Expression* reachingCondition = nullptr;
				auto iterPair = predecessors.equal_range(subregion);
				for (const auto& pair : make_range(iterPair.first, iterPair.second))
				{
					Expression* parentReachingCondition = reachingConditions.at(pair.second);
					PreAstBasicBlock* predExit;
					if (pair.second->isSubRegion())
					{
						predExit = pair.second->getNodeAs<Region>()->getExit();
					}
					else
					{
						predExit = pair.second->getNodeAs<PreAstBasicBlock>();
					}
					
					Expression* edgeCondition = nullptr;
					for (PreAstBasicBlockEdge* edge : predExit->successors)
					{
						if (edge->to == regionEntry)
						{
							if (edgeCondition == nullptr)
							{
								edgeCondition = edge->reachingCondition;
								break;
							}
							else
							{
								assert(*edgeCondition == *edge->reachingCondition);
							}
						}
					}
					assert(edgeCondition != nullptr);
					Expression* pathCondition = parentReachingCondition == nullptr
					? edgeCondition
					: ctx.nary(NAryOperatorExpression::ShortCircuitAnd, parentReachingCondition, edgeCondition);
					if (reachingCondition == nullptr)
					{
						reachingCondition = pathCondition;
					}
					else
					{
						reachingCondition = ctx.nary(NAryOperatorExpression::ShortCircuitOr, reachingCondition, pathCondition);
					}
				}
				
				auto result = reachingConditions.insert({subregion, reachingCondition});
				assert(result.second);
				(void) result;
				
				// Add statement to region.
				Statement* body = structurizeRegion(*subregion);
				seq->pushBack(ctx.ifElse(reachingCondition, body));
			}
			
			return seq;
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
	
	// Iterate regions in post-order.
	PreAstBasicBlockRegionTraits::RegionNodeT* rootNode = regionInfo.getTopLevelRegion()->getNode();
	auto body = Structurizer(result.getContext()).structurizeRegion(*rootNode);
	result.setBody(body);
}

INITIALIZE_PASS_BEGIN(AstBackEnd, "astbe", "AST Back-End", true, false)
INITIALIZE_PASS_END(AstBackEnd, "astbe", "AST Back-End", true, false)

AstBackEnd* createAstBackEnd()
{
	return new AstBackEnd;
}
