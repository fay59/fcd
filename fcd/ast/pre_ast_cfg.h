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

class PreAstBasicBlock;

struct PreAstBasicBlockEdge
{
	NOT_NULL(PreAstBasicBlock) from;
	NOT_NULL(PreAstBasicBlock) to;
	
	PreAstBasicBlockEdge(PreAstBasicBlock& from, PreAstBasicBlock& to)
	: from(&from), to(&to)
	{
	}
	
	void setFrom(PreAstBasicBlock& newFrom);
	void setTo(PreAstBasicBlock& newTo);
};

struct PreAstBasicBlock
{
	llvm::SmallVector<NOT_NULL(PreAstBasicBlockEdge), 8> predecessors;
	llvm::SmallVector<NOT_NULL(PreAstBasicBlockEdge), 2> successors;
	llvm::BasicBlock* block;
	
	void printAsOperand(llvm::raw_ostream& os, bool printType);
};

class PreAstContext
{
	llvm::Function& fn;
	std::deque<PreAstBasicBlockEdge> edgeList;
	std::deque<PreAstBasicBlock> blockList;
	std::unordered_map<llvm::BasicBlock*, PreAstBasicBlock*> blockMapping;
	
public:
	typedef decltype(blockList)::iterator node_iterator;
	
	PreAstContext(llvm::Function& fn);
	
	PreAstBasicBlock& createRedirectorBlock(llvm::ArrayRef<PreAstBasicBlockEdge*> redirectedEdgeList);
	
	PreAstBasicBlock* getEntryBlock()
	{
		return blockMapping.at(&fn.getEntryBlock());
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
