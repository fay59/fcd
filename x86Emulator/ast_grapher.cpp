//
//  ast_grapher.cpp
//  x86Emulator
//
//  Created by Félix on 2015-07-03.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#include "ast_grapher.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/DepthFirstIterator.h>
#include <llvm/IR/Instructions.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

#pragma mark - AST Graph Node
AstGraphNode::AstGraphNode(AstGrapher& grapher, Statement* node, llvm::BasicBlock* entry, llvm::BasicBlock* exit)
: grapher(grapher), node(node), entry(entry), exit(exit)
{
	assert(node && entry);
}

#pragma mark - AST Grapher
AstGrapher::AstGrapher(DumbAllocator& alloc)
: pool(alloc)
{
}

Statement* AstGrapher::addBasicBlock(BasicBlock& bb)
{
	SequenceNode* node = pool.allocate<SequenceNode>(pool);
	for (Instruction& inst : bb)
	{
		// Remove branch instructions at this step. Use basic blocks to figure out the conditions.
		if (!isa<BranchInst>(inst) && !isa<SwitchInst>(inst))
		{
			Expression* value = pool.allocate<ValueExpression>(inst);
			ExpressionNode* expressionNode = pool.allocate<ExpressionNode>(value);
			node->statements.push_back(expressionNode);
		}
	}
	
	nodeStorage.emplace_back(*this, node, &bb, &bb);
	nodeByEntry[&bb] = node;
	graphNodeByAstNode[node] = &nodeStorage.back();
	return node;
}

void AstGrapher::updateRegion(llvm::BasicBlock &entry, llvm::BasicBlock *exit, Statement &node)
{
	nodeStorage.emplace_back(*this, &node, &entry, exit);
	nodeByEntry[&entry] = &node;
	graphNodeByAstNode[&node] = &nodeStorage.back();
}

AstGraphNode* AstGrapher::getGraphNode(Statement* node)
{
	auto iter = graphNodeByAstNode.find(node);
	if (iter != graphNodeByAstNode.end())
	{
		return iter->second;
	}
	
	return nullptr;
}

AstGraphNode* AstGrapher::getGraphNodeFromEntry(llvm::BasicBlock* block)
{
	auto nodeIter = nodeByEntry.find(block);
	if (nodeIter != nodeByEntry.end())
	{
		return getGraphNode(nodeIter->second);
	}
	
	return nullptr;
}
