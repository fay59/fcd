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

#ifndef fcd__ast_visitor_h
#define fcd__ast_visitor_h

#include "statements.h"

class StatementVisitor
{
public:
	virtual void visitSequence(SequenceStatement* sequence);
	virtual void visitIfElse(IfElseStatement* ifElse);
	virtual void visitLoop(LoopStatement* loop);
	virtual void visitKeyword(KeywordStatement* keyword);
	virtual void visitExpression(ExpressionStatement* expression);
	
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
	virtual void visitSubscript(SubscriptExpression* subscript);
	virtual void visitAssembly(AssemblyExpression* assembly);
	virtual void visitAssignable(AssignableExpression* assignable);
	
	virtual ~ExpressionVisitor() = 0;
};

#endif /* fcd__ast_visitor_h */
