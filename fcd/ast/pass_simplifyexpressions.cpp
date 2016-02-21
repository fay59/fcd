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
	TokenExpression uninitialized("__uninitialized");
	
	inline UnaryOperatorExpression* match(Expression* expr, UnaryOperatorExpression::UnaryOperatorType type)
	{
		if (auto unary = dyn_cast_or_null<UnaryOperatorExpression>(expr))
		if (unary->type == type)
		{
			return unary;
		}
		
		return nullptr;
	}
	
	inline NAryOperatorExpression* match(Expression* expr, NAryOperatorExpression::NAryOperatorType type)
	{
		if (auto nary = dyn_cast_or_null<NAryOperatorExpression>(expr))
		if (nary->type == type)
		{
			return nary;
		}
		
		return nullptr;
	}
	
	inline UnaryOperatorExpression* asNegated(Expression* expr)
	{
		return match(expr, UnaryOperatorExpression::LogicalNegate);
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
	
	template<typename Map>
	auto valueOrNull(const Map& map, const typename Map::key_type& key)
	{
		auto iter = map.find(key);
		return iter == map.end() ? nullptr : iter->second;
	}
	
	Expression* replaceTwoFirstOperands(NAryOperatorExpression* nary, NOT_NULL(Expression) reduced)
	{
		if (nary->operands.size() < 3)
		{
			return reduced;
		}
		else
		{
			nary->operands[1] = reduced;
			nary->operands.erase_at(0);
			return nary;
		}
	}
	
	void removeIdenticalTerms(NAryOperatorExpression* nary)
	{
		// This is allowed on both && and ||, since (a && a) == a and (a || a) == a.
		assert(nary->type == NAryOperatorExpression::ShortCircuitAnd || nary->type == NAryOperatorExpression::ShortCircuitOr);
		SmallPtrSet<Expression*, 16> trueTerms;
		SmallPtrSet<Expression*, 16> falseTerms;
		size_t index = 0;
		while (index != nary->operands.size())
		{
			Expression* term = nary->operands[index];
			// If it's a new term, insert it and keep looking.
			if (auto neg = asNegated(term))
			{
				if (falseTerms.insert(neg->operand).second)
				{
					++index;
					continue;
				}
			}
			else if (trueTerms.insert(term).second)
			{
				++index;
				continue;
			}
			
			// If we've already encountered it, delete it.
			nary->operands.erase_at(index);
		}
	}
	
	void simplifySumOfProducts(NAryOperatorExpression* nary)
	{
		// remove terms in nested logical OR conditions.
		SmallPtrSet<Expression*, 8> mustBeTrue;
		SmallPtrSet<Expression*, 8> mustBeFalse;
		vector<pair<NAryOperatorExpression*, size_t>> logicalOrs;
		
		size_t i = 0;
		for (Expression* expr : nary->operands)
		{
			if (auto shortCircuitOr = match(expr, NAryOperatorExpression::ShortCircuitOr))
			{
				logicalOrs.emplace_back(shortCircuitOr, i);
			}
			else if (auto neg = asNegated(expr))
			{
				mustBeFalse.insert(neg->operand);
			}
			else
			{
				mustBeTrue.insert(expr);
			}
			++i;
		}
		
		for (auto iter = logicalOrs.rbegin(); iter != logicalOrs.rend(); ++iter)
		{
			bool alwaysTrue = false;
			auto expr = iter->first;
			size_t i = 0;
			
			// Iteratively strip operands from the logical OR condition.
			// If one operand is proven to be always true, remove the OR condition
			// entirely, since (a && true) == a.
			while (i < expr->operands.size())
			{
				Expression* operand = expr->operands[i];
				if (auto neg = asNegated(operand))
				{
					if (mustBeFalse.count(neg->operand) != 0)
					{
						alwaysTrue = true;
						break;
					}
					else if (mustBeTrue.count(neg->operand) != 0)
					{
						expr->operands.erase_at(i);
						continue;
					}
				}
				else if (mustBeTrue.count(operand) != 0)
				{
					alwaysTrue = true;
					break;
				}
				else if (mustBeFalse.count(operand) != 0)
				{
					expr->operands.erase_at(i);
					continue;
				}
				++i;
			}
			
			if (alwaysTrue)
			{
				// no need for this condition
				nary->operands.erase_at(iter->second);
			}
			else
			{
				// Remove logical ORs that have been entirely stripped.
				if (i == 1)
				{
					nary->operands[iter->second] = expr->operands[0];
				}
				else if (i == 0)
				{
					nary->operands.erase_at(iter->second);
				}
			}
		}
	}
}

Expression* AstSimplifyExpressions::simplify(Expression *expr)
{
	if (expr == nullptr)
	{
		return nullptr;
	}
	
	expr->visit(*this);
	if (auto nary = dyn_cast<NAryOperatorExpression>(result))
	{
		assert(nary->operands.size() > 0);
	}
	return result;
}

void AstSimplifyExpressions::visitIfElse(IfElseStatement *ifElse)
{
	ifElse->condition = unwrapNegatedAll(simplify(ifElse->condition));
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
	
	if (assignment->isSsa)
	if (auto left = dyn_cast<TokenExpression>(assignment->left))
	if (auto addressOf = match(assignment->right, UnaryOperatorExpression::AddressOf))
	{
		auto result = addressesOf.insert({left, addressOf->operand});
		assert(result.second);
	}
}

void AstSimplifyExpressions::visitUnary(UnaryOperatorExpression *unary)
{
	unary->operand = simplify(unary->operand);
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
	else if (unary->type == UnaryOperatorExpression::Dereference)
	{
		if (auto innerAddressOf = match(unary->operand, UnaryOperatorExpression::AddressOf))
		{
			result = simplify(innerAddressOf->operand);
		}
		else if (auto token = dyn_cast<TokenExpression>(unary->operand))
		{
			auto iter = addressesOf.find(token);
			if (iter != addressesOf.end())
			{
				result = iter->second;
			}
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
	
	if (nary->type == NAryOperatorExpression::MemberAccess)
	{
		if (auto left = dyn_cast<SubscriptExpression>(nary->operands[0]))
		if (auto constantIndex = dyn_cast<NumericExpression>(left->index))
		if (constantIndex->ui64 == 0)
		{
			auto pointerAccess = pool().allocate<NAryOperatorExpression>(pool(), NAryOperatorExpression::PointerAccess);
			pointerAccess->operands.push_back(left->left);
			pointerAccess->operands.push_back(nary->operands[1]);
			result = simplify(replaceTwoFirstOperands(nary, pointerAccess));
		}
	}
	else if (nary->type == NAryOperatorExpression::PointerAccess)
	{
		if (auto leftToken = dyn_cast<TokenExpression>(nary->operands[0]))
		if (auto addressTaken = valueOrNull(addressesOf, leftToken))
		{
			auto memberAccess = pool().allocate<NAryOperatorExpression>(pool(), NAryOperatorExpression::MemberAccess);
			memberAccess->operands.push_back(addressTaken);
			memberAccess->operands.push_back(nary->operands[1]);
			result = simplify(replaceTwoFirstOperands(nary, memberAccess));
		}
	}
	else if (nary->type == NAryOperatorExpression::ShortCircuitAnd)
	{
		removeIdenticalTerms(nary);
		simplifySumOfProducts(nary);
	}
	else if (nary->type == NAryOperatorExpression::ShortCircuitOr)
	{
		removeIdenticalTerms(nary);
	}
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

void AstSimplifyExpressions::visitSubscript(SubscriptExpression *subscript)
{
	subscript->left = simplify(subscript->left);
	subscript->index = simplify(subscript->index);
	result = subscript;
}

void AstSimplifyExpressions::visitAssembly(AssemblyExpression *assembly)
{
	result = assembly;
}

void AstSimplifyExpressions::doRun(FunctionNode &fn)
{
	fn.body->visit(*this);
}

AstSimplifyExpressions::AstSimplifyExpressions()
: result(&uninitialized)
{
}

const char* AstSimplifyExpressions::getName() const
{
	return "Simplify conditions";
}
