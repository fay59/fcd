//
// pass_structuretree.cpp
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

#include "pass_structuretree.h"

StructureTreeNode* AstStructureTree::visit(Statement* statement)
{
	statement->visit(*this);
	return result;
}

StructureTreeNode* AstStructureTree::createNode(Statement *statement)
{
	auto thisNode = pool().allocate<StructureTreeNode>(statement);
	structureTree.insert({statement, thisNode});
	return thisNode;
}

void AstStructureTree::visitSequence(SequenceNode *sequence)
{
	StructureTreeNode* thisNode = createNode(sequence);
	for (auto statement : sequence->statements)
	{
		visit(statement)->parent = thisNode;
	}
	result = thisNode;
}

void AstStructureTree::visitIfElse(IfElseNode *ifElse)
{
	StructureTreeNode* thisNode = createNode(ifElse);
	visit(ifElse->ifBody)->parent = thisNode;
	if (ifElse->elseBody != nullptr)
	{
		visit(ifElse->elseBody)->parent = thisNode;
	}
	result = thisNode;
}

void AstStructureTree::visitLoop(LoopNode *loop)
{
	StructureTreeNode* thisNode = createNode(loop);
	visit(loop->loopBody)->parent = thisNode;
	result = thisNode;
}

void AstStructureTree::visitKeyword(KeywordNode *keyword)
{
	result = createNode(keyword);
}

void AstStructureTree::visitExpression(ExpressionNode *expression)
{
	result = createNode(expression);
}

void AstStructureTree::visitDeclaration(DeclarationNode *declaration)
{
	result = createNode(declaration);
}

void AstStructureTree::visitAssignment(AssignmentNode *assignment)
{
	result = createNode(assignment);
}

void AstStructureTree::doRun(FunctionNode &fn)
{
	fn.body->visit(*this);
}

StructureTreeNodeIterator AstStructureTree::begin(Statement *statement)
{
	return StructureTreeNodeIterator(structureTree.at(statement));
}

const char* AstStructureTree::getName() const
{
	return "Control structures tree";
}
