//
// pass_structuretree.h
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

#ifndef pass_structuretree_cpp
#define pass_structuretree_cpp

#include "pass.h"
#include "visitor.h"

#include <iterator>
#include <map>

struct StructureTreeNode
{
	StructureTreeNode* parent;
	Statement* statement;
	
	inline StructureTreeNode(Statement* statement)
	: parent(nullptr), statement(statement)
	{
	}
};

class StructureTreeNodeIterator : public std::iterator<std::forward_iterator_tag, Statement, void>
{
	StructureTreeNode* current;
	
public:
	inline StructureTreeNodeIterator(StructureTreeNode* current)
	: current(current)
	{
	}
	
	inline Statement& operator*() { return *operator->(); }
	inline Statement* operator->() { return current->statement; }
	inline StructureTreeNodeIterator& operator++()
	{
		current = current->parent;
		return *this;
	}
	
	inline bool operator==(const StructureTreeNodeIterator& that) const
	{
		return current == that.current;
	}
	
	inline bool operator!=(const StructureTreeNodeIterator& that) const
	{
		return !(*this == that);
	}
};

class AstStructureTree : public AstPass, private StatementVisitor
{
	StructureTreeNode* result;
	std::map<Statement*, StructureTreeNode*> structureTree;
	
	StructureTreeNode* visit(Statement* statement);
	StructureTreeNode* createNode(Statement* statement);
	
	virtual void visitSequence(SequenceNode* sequence) override;
	virtual void visitIfElse(IfElseNode* ifElse) override;
	virtual void visitLoop(LoopNode* loop) override;
	virtual void visitKeyword(KeywordNode* keyword) override;
	virtual void visitExpression(ExpressionNode* expression) override;
	virtual void visitDeclaration(DeclarationNode* declaration) override;
	virtual void visitAssignment(AssignmentNode* assignment) override;
	
protected:
	virtual void doRun(FunctionNode& fn) override;
	
public:
	StructureTreeNodeIterator begin(Statement* statement);
	inline StructureTreeNodeIterator end() const { return StructureTreeNodeIterator(nullptr); }
	
	virtual const char* getName() const override;
};

#endif /* pass_structuretree_cpp */
