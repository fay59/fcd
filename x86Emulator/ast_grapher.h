//
//  ast_grapher.hpp
//  x86Emulator
//
//  Created by Félix on 2015-07-03.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#ifndef ast_grapher_cpp
#define ast_grapher_cpp

#include "ast_nodes.h"
#include "dumb_allocator.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/CFG.h>
SILENCE_LLVM_WARNINGS_END()

#include <unordered_map>
#include <deque>

class AstGrapher;

class AstGraphNode
{
	friend class llvm::GraphTraits<AstGraphNode>;
	AstGrapher& grapher;
	
	llvm::BasicBlock* entry;
	llvm::BasicBlock* exit;
	
public:
	Statement* node;
	
	AstGraphNode(AstGrapher& grapher, Statement* node, llvm::BasicBlock* entry, llvm::BasicBlock* exit);
	
	inline llvm::BasicBlock* getEntry() { return entry; }
	inline bool hasExit() { return entry != exit; }
	inline llvm::BasicBlock* getExit() { return exit; }
};

class AstGrapher
{
	DumbAllocator& pool;
	std::deque<AstGraphNode> nodeStorage;
	std::unordered_map<llvm::BasicBlock*, Statement*> nodeByEntry;
	std::unordered_map<Statement*, AstGraphNode*> graphNodeByAstNode;
	
public:
	typedef decltype(nodeStorage)::iterator nodes_iterator;
	
	explicit AstGrapher(DumbAllocator& pool);
	
	Statement* addBasicBlock(llvm::BasicBlock& bb);
	void updateRegion(llvm::BasicBlock& entry, llvm::BasicBlock* exit, Statement& node);
	
	AstGraphNode* getGraphNode(Statement* node);
	AstGraphNode* getGraphNodeFromEntry(llvm::BasicBlock* block);
	
	inline nodes_iterator begin()
	{
		return nodeStorage.begin();
	}
	
	inline nodes_iterator end()
	{
		return nodeStorage.end();
	}
	
	inline auto size()
	{
		return nodeStorage.size();
	}
};

#endif /* ast_grapher_cpp */
