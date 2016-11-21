//
// pre_ast_cfg.h
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

#ifndef pre_ast_cfg_h
#define pre_ast_cfg_h

#include "not_null.h"

#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Function.h>

#include <deque>
#include <unordered_map>

class AstContext;
class Expression;
class PreAstBasicBlock;

struct PreAstBasicBlockEdge
{
	NOT_NULL(PreAstBasicBlock) from;
	NOT_NULL(PreAstBasicBlock) to;
	NOT_NULL(Expression) edgeCondition;
	
	PreAstBasicBlockEdge(PreAstBasicBlock& from, PreAstBasicBlock& to, Expression& edgeCondition)
	: from(&from), to(&to), edgeCondition(&edgeCondition)
	{
	}
	
	void setTo(PreAstBasicBlock& newTo);
};

struct PreAstBasicBlock
{
	llvm::SmallVector<NOT_NULL(PreAstBasicBlockEdge), 8> predecessors;
	llvm::SmallVector<NOT_NULL(PreAstBasicBlockEdge), 2> successors;
	
	SequenceStatement* blockStatement;
	
	// At most one of these should be set at any time.
	llvm::BasicBlock* block;
	Expression* sythesizedVariable;
	
	void printAsOperand(llvm::raw_ostream& os, bool printType);
};

class PreAstContext
{
	AstContext& ctx;
	std::deque<PreAstBasicBlockEdge> edgeList;
	std::deque<PreAstBasicBlock> blockList;
	std::unordered_map<llvm::BasicBlock*, PreAstBasicBlock*> blockMapping;
	
public:
	typedef decltype(blockList)::iterator node_iterator;
	
	PreAstContext(AstContext& ctx);
	
	void generateBlocks(llvm::Function& fn);
	
	PreAstBasicBlock& createRedirectorBlock(llvm::ArrayRef<PreAstBasicBlockEdge*> redirectedEdgeList);
	
	PreAstBasicBlockEdge& createEdge(PreAstBasicBlock& from, PreAstBasicBlock& to, Expression& edgeCondition)
	{
		edgeList.emplace_back(from, to, edgeCondition);
		return edgeList.back();
	}
	
	PreAstBasicBlock& createBlock()
	{
		blockList.emplace_back();
		return blockList.back();
	}
	
	PreAstBasicBlock* getEntryBlock()
	{
		return &blockList.front();
	}
	
	node_iterator begin()
	{
		return blockList.begin();
	}
	
	node_iterator end()
	{
		return blockList.end();
	}
	
	size_t size() const
	{
		return blockList.size();
	}
};

#endif /* pre_ast_cfg_hpp */
