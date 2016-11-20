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
			SmallVector<PreAstBasicBlockEdge*, 16> enteringEdges;
			SmallVector<PreAstBasicBlockEdge*, 16> exitingEdges;
			for (PreAstBasicBlock* bb : scc)
			{
				for (PreAstBasicBlockEdge* edge : bb->predecessors)
				{
					if (sccSet.count(edge->from) == 0)
					{
						enteringEdges.push_back(edge);
					}
				}
				for (PreAstBasicBlockEdge* edge : bb->successors)
				{
					if (sccSet.count(edge->to) == 0)
					{
						exitingEdges.push_back(edge);
					}
				}
			}
			
			if (enteringEdges.size() > 1)
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
			
			if (exitingEdges.size() > 1)
			{
				function.createRedirectorBlock(exitingEdges);
			}
		}
	}
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
	blockGraph.reset(new PreAstContext(fn));
	
	// First, ensure that blocks all have a single entry and a single exit.
	ensureSingleEntrySingleExitCycles(*blockGraph);
	
	// Next, compute regions.
	PreAstBasicBlockRegionTraits::DomTreeT domTree(false);
	PreAstBasicBlockRegionTraits::PostDomTreeT postDomTree(true);
	PreAstBasicBlockRegionTraits::DomFrontierT dominanceFrontier;
	PreAstBasicBlockRegionTraits::RegionInfoT regions;
	domTree.recalculate(*blockGraph);
	domTree.recalculate(*blockGraph);
	dominanceFrontier.analyze(domTree);
	regions.recalculate(*blockGraph, &domTree, &postDomTree, &dominanceFrontier);
}

void AstBackEnd::runOnLoop(Function& fn, BasicBlock& entry, BasicBlock* exit)
{
}

void AstBackEnd::runOnRegion(Function& fn, BasicBlock& entry, BasicBlock* exit)
{
}

INITIALIZE_PASS_BEGIN(AstBackEnd, "astbe", "AST Back-End", true, false)
INITIALIZE_PASS_END(AstBackEnd, "astbe", "AST Back-End", true, false)

AstBackEnd* createAstBackEnd()
{
	return new AstBackEnd;
}
