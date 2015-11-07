//
// visitor.cpp
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

#include "visitor.h"

void StatementVisitor::visitSequence(SequenceNode* sequence)
{
	for (auto statement : sequence->statements)
	{
		statement->visit(*this);
	}
}

void StatementVisitor::visitIfElse(IfElseNode* ifElse)
{
	ifElse->ifBody->visit(*this);
	if (ifElse->elseBody != nullptr)
	{
		ifElse->elseBody->visit(*this);
	}
}

void StatementVisitor::visitLoop(LoopNode* loop)
{
	loop->loopBody->visit(*this);
}

void StatementVisitor::visitKeyword(KeywordNode* keyword)
{
}

void StatementVisitor::visitExpression(ExpressionNode* expression)
{
}

void StatementVisitor::visitDeclaration(DeclarationNode* declaration)
{
}

void StatementVisitor::visitAssignment(AssignmentNode* assignment)
{
}

StatementVisitor::~StatementVisitor()
{
}

void ExpressionVisitor::visitUnary(UnaryOperatorExpression* unary)
{
	unary->operand->visit(*this);
}

void ExpressionVisitor::visitNAry(NAryOperatorExpression* nary)
{
	for (auto expr : nary->operands)
	{
		expr->visit(*this);
	}
}

void ExpressionVisitor::visitTernary(TernaryExpression* ternary)
{
	ternary->condition->visit(*this);
	ternary->ifTrue->visit(*this);
	ternary->ifFalse->visit(*this);
}

void ExpressionVisitor::visitNumeric(NumericExpression* numeric)
{
}

void ExpressionVisitor::visitToken(TokenExpression* token)
{
}

void ExpressionVisitor::visitCall(CallExpression* call)
{
	call->callee->visit(*this);
	for (auto arg : call->parameters)
	{
		arg->visit(*this);
	}
}

void ExpressionVisitor::visitCast(CastExpression* cast)
{
	cast->type->visit(*this);
	cast->casted->visit(*this);
}

void ExpressionVisitor::visitAggregate(AggregateExpression* aggregate)
{
	for (auto arg : aggregate->values)
	{
		arg->visit(*this);
	}
}

ExpressionVisitor::~ExpressionVisitor()
{
}
