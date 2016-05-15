//
// grapher.cpp
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

#include "grapher.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/DepthFirstIterator.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

#pragma mark - AST Graph Node
AstGraphNode::AstGraphNode(AstGrapher& grapher, Statement* node, llvm::BasicBlock* entry, llvm::BasicBlock* exit)
: grapher(grapher), entry(entry), exit(exit), node(node)
{
	assert(node && entry);
}

#pragma mark - AST Grapher
void AstGrapher::createRegion(llvm::BasicBlock &bb, Statement &node)
{
	nodeStorage.emplace_back(*this, &node, &bb, &bb);
	nodeByEntry[&bb] = &node;
	graphNodeByAstNode[&node] = &nodeStorage.back();
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
