//
// clone.cpp
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

#include "clone.h"

void ExpressionCloneVisitor::visitUnary(UnaryOperatorExpression *unary)
{
	result = pool.allocate<UnaryOperatorExpression>(unary->type, clone(unary->operand));
}

void ExpressionCloneVisitor::visitNAry(NAryOperatorExpression *nary)
{
	NAryOperatorExpression* copy = pool.allocate<NAryOperatorExpression>(pool, nary->type);
	for (auto operand : nary->operands)
	{
		copy->addOperand(clone(operand));
	}
	result = copy;
}

void ExpressionCloneVisitor::visitTernary(TernaryExpression *ternary)
{
	result = pool.allocate<TernaryExpression>(clone(ternary->condition), clone(ternary->ifTrue), clone(ternary->ifFalse));
}

void ExpressionCloneVisitor::visitNumeric(NumericExpression *numeric)
{
	result = pool.allocate<NumericExpression>(numeric->ui64);
}

void ExpressionCloneVisitor::visitToken(TokenExpression *token)
{
	// Don't copy global tokens.
	if (token == TokenExpression::trueExpression || token == TokenExpression::falseExpression || token == TokenExpression::undefExpression)
	{
		result = token;
		return;
	}
	
	result = pool.allocate<TokenExpression>(pool, static_cast<const char*>(token->token));
}

void ExpressionCloneVisitor::visitCall(CallExpression *call)
{
	auto copy = pool.allocate<CallExpression>(pool, clone(call->callee));
	for (auto param : call->parameters)
	{
		copy->parameters.push_back(clone(param));
	}
	result = copy;
}

void ExpressionCloneVisitor::visitCast(CastExpression *cast)
{
	result = pool.allocate<CastExpression>(static_cast<TokenExpression*>(clone(cast->type)), clone(cast->casted), cast->sign);
}

void ExpressionCloneVisitor::visitAggregate(AggregateExpression *agg)
{
	auto copy = pool.allocate<AggregateExpression>(pool);
	for (auto value : agg->values)
	{
		copy->values.push_back(clone(value));
	}
	result = copy;
}

void ExpressionCloneVisitor::visitSubscript(SubscriptExpression *subscript)
{
	result = pool.allocate<SubscriptExpression>(clone(subscript->left), subscript->index);
}

Expression* ExpressionCloneVisitor::clone(DumbAllocator &pool, Expression *that)
{
	return ExpressionCloneVisitor(pool).clone(that);
}

Expression* ExpressionCloneVisitor::clone(Expression* that)
{
	Expression*& existingClone = cloned[that];
	if (existingClone == nullptr)
	{
		that->visit(*this);
		existingClone = result;
	}
	return existingClone;
}
