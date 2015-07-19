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
	explicit AstGrapher(DumbAllocator& pool);
	
	void createRegion(llvm::BasicBlock& entry, Statement& node);
	void updateRegion(llvm::BasicBlock& entry, llvm::BasicBlock* exit, Statement& node);
	
	AstGraphNode* getGraphNode(Statement* node);
	AstGraphNode* getGraphNodeFromEntry(llvm::BasicBlock* block);
};

#endif /* ast_grapher_cpp */
