//
// pre_ast_cfg.cpp
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

#include "pre_ast_cfg.h"
#include "pre_ast_cfg_traits.h"

#include <llvm/Analysis/RegionInfoImpl.h>
#include <llvm/IR/CFG.h>
#include <llvm/Support/raw_ostream.h>

using namespace llvm;
using namespace std;

void PreAstBasicBlockEdge::setFrom(PreAstBasicBlock& newFrom)
{
	for (auto iter = from->successors.begin(); iter != from->successors.end(); ++iter)
	{
		if (*iter == this)
		{
			from->successors.erase(iter);
			newFrom.successors.push_back(this);
			from = &newFrom;
			return;
		}
	}
	
	llvm_unreachable("Edge not found in successor!");
}

void PreAstBasicBlockEdge::setTo(PreAstBasicBlock& newTo)
{
	for (auto iter = to->predecessors.begin(); iter != to->predecessors.end(); ++iter)
	{
		if (*iter == this)
		{
			to->predecessors.erase(iter);
			newTo.predecessors.push_back(this);
			to = &newTo;
			return;
		}
	}
	
	llvm_unreachable("Edge not found in predecessor!");
}

void PreAstBasicBlock::printAsOperand(llvm::raw_ostream& os, bool printType)
{
	if (block == nullptr)
	{
		os << "(synthesized block)";
	}
	else
	{
		block->printAsOperand(os, printType);
	}
}

PreAstContext::PreAstContext(Function& fn)
: fn(fn)
{
	for (BasicBlock& bb : fn)
	{
		blockList.emplace_back();
		PreAstBasicBlock& preAstBB = blockList.back();
		preAstBB.block = &bb;
		blockMapping.insert({&bb, &preAstBB});
	}
	
	for (BasicBlock& bb : fn)
	{
		PreAstBasicBlock& preAstBB = *blockMapping.at(&bb);
		for (BasicBlock* pred : predecessors(&bb))
		{
			PreAstBasicBlock& predAstBB = *blockMapping.at(pred);
			edgeList.emplace_back(predAstBB, preAstBB);
			PreAstBasicBlockEdge& edge = edgeList.back();
			preAstBB.predecessors.push_back(&edge);
			predAstBB.successors.push_back(&edge);
		}
	}
}

PreAstBasicBlock& PreAstContext::createRedirectorBlock(ArrayRef<PreAstBasicBlockEdge*> redirectedEdgeList)
{
	blockList.emplace_back();
	PreAstBasicBlock& newBlock = blockList.back();
	for (auto edge : redirectedEdgeList)
	{
		edgeList.emplace_back(newBlock, *edge->to);
		PreAstBasicBlockEdge& newEdge = edgeList.back();
		newEdge.from->successors.push_back(&newEdge);
		newEdge.to->predecessors.push_back(&newEdge);
		edge->setTo(newBlock);
	}
	return newBlock;
}

PreAstRegionInfo::PreAstRegionInfo()
{
}

void PreAstRegionInfo::recalculate(FuncT& function, DomTreeT* domTree, PostDomTreeT* postDomTree, DomFrontierT* dominanceFrontier)
{
	DT = domTree;
	PDT = postDomTree;
	DF = dominanceFrontier;
	TopLevelRegion = new RegionBase<PreAstBasicBlockRegionTraits>(function.getEntryBlock(), nullptr, this, domTree, nullptr);
	calculate(function);
}

void PreAstRegionInfo::updateStatistics(RegionT* region)
{
}
