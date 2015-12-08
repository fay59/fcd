//
// pass_simplifyconditions.cpp
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

#include "pass_simplifyexpressions.h"

using namespace llvm;
using namespace std;

namespace
{
	inline UnaryOperatorExpression* asNegated(Expression* expr)
	{
		if (auto unary = dyn_cast_or_null<UnaryOperatorExpression>(expr))
		if (unary->type == UnaryOperatorExpression::LogicalNegate)
		{
			return unary;
		}
		
		return nullptr;
	}
	
	inline Expression* unwrapNegated(Expression* maybeNegated)
	{
		if (auto outerNegated = asNegated(maybeNegated))
		if (auto innerNegated = asNegated(outerNegated->operand))
		{
			return innerNegated->operand;
		}
		return maybeNegated;
	}
	
	Expression* unwrapNegatedAll(Expression* maybeNegated)
	{
		auto unwrapped = unwrapNegated(maybeNegated);
		while (unwrapped != maybeNegated)
		{
			maybeNegated = unwrapped;
			unwrapped = unwrapNegated(maybeNegated);
		}
		return unwrapped;
	}
	
	inline NAryOperatorExpression* changeOperator(DumbAllocator& pool, NAryOperatorExpression* expr, NAryOperatorExpression::NAryOperatorType op)
	{
		auto result = pool.allocate<NAryOperatorExpression>(pool, op);
		result->addOperands(expr->operands.begin(), expr->operands.end());
		return result;
	}
	
	Expression* distributeNegation(DumbAllocator& pool, Expression* maybeNegated)
	{
		if (auto unary = asNegated(maybeNegated))
		if (auto nary = dyn_cast<NAryOperatorExpression>(unary->operand))
		if (nary->operands.size() == 2)
		{
			switch (nary->type)
			{
				case NAryOperatorExpression::SmallerThan:
					return changeOperator(pool, nary, NAryOperatorExpression::GreaterOrEqualTo);
					
				case NAryOperatorExpression::GreaterOrEqualTo:
					return changeOperator(pool, nary, NAryOperatorExpression::SmallerThan);
					
				case NAryOperatorExpression::GreaterThan:
					return changeOperator(pool, nary, NAryOperatorExpression::SmallerOrEqualTo);
					
				case NAryOperatorExpression::SmallerOrEqualTo:
					return changeOperator(pool, nary, NAryOperatorExpression::GreaterThan);
					
				case NAryOperatorExpression::Equal:
					return changeOperator(pool, nary, NAryOperatorExpression::NotEqual);
					
				case NAryOperatorExpression::NotEqual:
					return changeOperator(pool, nary, NAryOperatorExpression::Equal);
					
				default: break;
			}
		}
		return maybeNegated;
	}
}

Expression* AstSimplifyExpressions::simplify(Expression *expr)
{
	if (expr == nullptr)
	{
		return nullptr;
	}
	
	expr->visit(*this);
	return result;
}

void AstSimplifyExpressions::visitIfElse(IfElseStatement *ifElse)
{
	ifElse->condition = unwrapNegatedAll(ifElse->condition);
	if (auto stillNegated = asNegated(ifElse->condition))
	{
		if (auto elseBody = ifElse->elseBody)
		{
			ifElse->condition = stillNegated->operand;
			ifElse->elseBody = ifElse->ifBody;
			ifElse->ifBody = elseBody;
		}
		else
		{
			ifElse->condition = distributeNegation(pool(), stillNegated);
		}
	}
	
	StatementVisitor::visitIfElse(ifElse);
}

void AstSimplifyExpressions::visitLoop(LoopStatement *loop)
{
	loop->condition = simplify(loop->condition);
	StatementVisitor::visitLoop(loop);
}

void AstSimplifyExpressions::visitKeyword(KeywordStatement *keyword)
{
	keyword->operand = simplify(keyword->operand);
}

void AstSimplifyExpressions::visitExpression(ExpressionStatement *expression)
{
	expression->expression = simplify(expression->expression);
}

void AstSimplifyExpressions::visitAssignment(AssignmentStatement *assignment)
{
	assignment->left = simplify(assignment->left);
	assignment->right = simplify(assignment->right);
}

void AstSimplifyExpressions::visitUnary(UnaryOperatorExpression *unary)
{
	result = unary;
	if (unary->type == UnaryOperatorExpression::LogicalNegate)
	{
		if (auto innerNegated = asNegated(unary->operand))
		{
			result = simplify(innerNegated->operand);
		}
		else
		{
			result = distributeNegation(pool(), unary);
		}
	}
}

void AstSimplifyExpressions::visitNAry(NAryOperatorExpression *nary)
{
	for (auto& expr : nary->operands)
	{
		expr = simplify(expr);
	}
	result = nary;
}

void AstSimplifyExpressions::visitToken(TokenExpression *token)
{
	result = token;
}

void AstSimplifyExpressions::visitNumeric(NumericExpression *numeric)
{
	result = numeric;
}

void AstSimplifyExpressions::visitTernary(TernaryExpression *ternary)
{
	ternary->condition = simplify(ternary->condition);
	ternary->ifTrue = simplify(ternary->ifTrue);
	ternary->ifFalse = simplify(ternary->ifFalse);
	result = ternary;
}

void AstSimplifyExpressions::visitCall(CallExpression *call)
{
	call->callee = simplify(call->callee);
	for (auto& param : call->parameters)
	{
		param = simplify(param);
	}
	result = call;
}

void AstSimplifyExpressions::visitCast(CastExpression *cast)
{
	cast->casted = simplify(cast->casted);
	result = cast;
}

void AstSimplifyExpressions::visitAggregate(AggregateExpression *aggregate)
{
	for (auto& value : aggregate->values)
	{
		value = simplify(value);
	}
	result = aggregate;
}

void AstSimplifyExpressions::doRun(FunctionNode &fn)
{
	fn.body->visit(*this);
}

const char* AstSimplifyExpressions::getName() const
{
	return "Simplify conditions";
}
