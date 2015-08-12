//
// grapher.h
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

#ifndef ast_grapher_cpp
#define ast_grapher_cpp

#include "nodes.h"
#include "dumb_allocator.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/CFG.h>
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <unordered_map>
#include <deque>

class AstGrapher;

class AstGraphNode
{
	friend class llvm::GraphTraits<AstGraphNode>;
	AstGrapher& grapher;
	
	llvm::BasicBlock* entry;
	
	// Exit is special as it is *non-inclusive*. The exit node of a region is not considered a part of that region.
	// It can take on two special values: nullptr (the region has "no exit", ie it finishes at the end of the function),
	// or the same value as entry.
	// Under this definition, a region with entry==exit means an empty region. Since this is not possible, we use this
	// special case to denote that the region hasn't been structured: it's only a basic block with posibly multiple
	// successors. This state is temporary.
	llvm::BasicBlock* exit;
	
public:
	Statement* node;
	
	AstGraphNode(AstGrapher& grapher, Statement* node, llvm::BasicBlock* entry, llvm::BasicBlock* exit);
	
	inline llvm::BasicBlock* getEntry() { return entry; }
	inline const llvm::BasicBlock* getEntry() const { return entry; }
	inline llvm::BasicBlock* getExit() { return exit; }
	inline bool hasExit() const { return entry != exit; }
};

class AstGrapher
{
	DumbAllocator& pool;
	std::deque<AstGraphNode> nodeStorage;
	std::unordered_map<llvm::BasicBlock*, Statement*> nodeByEntry;
	std::unordered_map<Statement*, AstGraphNode*> graphNodeByAstNode;
	
public:
	typedef decltype(nodeStorage)::const_iterator const_iterator;
	
	explicit AstGrapher(DumbAllocator& pool);
	
	void createRegion(llvm::BasicBlock& entry, Statement& node);
	void updateRegion(llvm::BasicBlock& entry, llvm::BasicBlock* exit, Statement& node);
	
	AstGraphNode* getGraphNode(Statement* node);
	AstGraphNode* getGraphNodeFromEntry(llvm::BasicBlock* block);
	
	inline const_iterator begin() const { return nodeStorage.begin(); }
	inline const_iterator end() const { return nodeStorage.end(); }
};

#endif /* ast_grapher_cpp */
