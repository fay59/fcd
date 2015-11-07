//
// visitor.h
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

#ifndef ast_visitor_cpp
#define ast_visitor_cpp

#include "nodes.h"

class StatementVisitor
{
public:
	virtual void visitSequence(SequenceNode* sequence);
	virtual void visitIfElse(IfElseNode* ifElse);
	virtual void visitLoop(LoopNode* loop);
	virtual void visitKeyword(KeywordNode* keyword);
	virtual void visitExpression(ExpressionNode* expression);
	virtual void visitDeclaration(DeclarationNode* declaration);
	virtual void visitAssignment(AssignmentNode* assignment);
	
	virtual ~StatementVisitor() = 0;
};

class ExpressionVisitor
{
public:
	virtual void visitUnary(UnaryOperatorExpression* unary);
	virtual void visitNAry(NAryOperatorExpression* nary);
	virtual void visitTernary(TernaryExpression* ternary);
	virtual void visitNumeric(NumericExpression* numeric);
	virtual void visitToken(TokenExpression* token);
	virtual void visitCall(CallExpression* call);
	virtual void visitCast(CastExpression* cast);
	virtual void visitAggregate(AggregateExpression* aggregate);
	
	virtual ~ExpressionVisitor() = 0;
};

#endif /* ast_visitor_cpp */
