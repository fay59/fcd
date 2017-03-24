//
// expressions.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "ast_context.h"
#include "expressions.h"
#include "function.h"
#include "statements.h"
#include "print.h"

#include <llvm/Support/raw_os_ostream.h>

#include <cstring>
#include <deque>
#include <unordered_set>

using namespace llvm;
using namespace std;

namespace
{
	template<typename Collection, typename Iter>
	void collectPointers(Collection& coll, Iter begin, Iter end)
	{
		for (auto iter = begin; iter != end; ++iter)
		{
			coll.push_back(&*iter);
		}
	}
	
	void getAncestry(SmallVectorImpl<NOT_NULL(Statement)>& ancestry, Statement& statement)
	{
		ancestry.clear();
		for (Statement* current = &statement; current != nullptr; current = current->getParent())
		{
			ancestry.push_back(current);
		}
		reverse(ancestry.begin(), ancestry.end());
	}
}

bool Expression::defaultEqualityCheck(const Expression &a, const Expression &b)
{
	const Expression* innerA = &a;
	const Expression* innerB = &b;
	
	while (auto nary = dyn_cast<NAryOperatorExpression>(innerA))
	{
		if (nary->operands_size() == 1)
		{
			innerA = nary->getOperand(0);
		}
		else
		{
			break;
		}
	}
	
	while (auto nary = dyn_cast<NAryOperatorExpression>(innerB))
	{
		if (nary->operands_size() == 1)
		{
			innerB = nary->getOperand(0);
		}
		else
		{
			break;
		}
	}
	
	if (innerA->getUserType() == innerB->getUserType() && innerA->operands_size() == innerB->operands_size())
	{
		return std::equal(innerA->operands_begin(), innerA->operands_end(), innerB->operands_begin(), [](const Expression* a, const Expression* b)
		{
			return *a == *b;
		});
	}
	return false;
}

unsigned Expression::uses_size() const
{
	unsigned size = 0;
	for (auto iter = uses_begin(); iter != uses_end(); ++iter)
	{
		++size;
	}
	return size;
}

void Expression::replaceAllUsesWith(Expression *expression)
{
	if (expression == this)
	{
		return;
	}
	
	while (auto use = firstUse)
	{
		use->setUse(expression);
	}
}

Statement* Expression::ancestorOfAllUses()
{
	// collect all user statements then find their common ancestor
	std::deque<Statement*> statements;
	std::unordered_set<ExpressionUser*> users;
	std::deque<ExpressionUse*> allUses;
	collectPointers(allUses, uses_begin(), uses_end());
	while (allUses.size() > 0)
	{
		auto iter = allUses.begin();
		auto user = (*iter)->getUser();
		allUses.erase(iter);
		if (users.insert(user).second)
		{
			if (auto stmt = dyn_cast<Statement>(user))
			{
				statements.push_back(stmt);
			}
			else
			{
				auto expr = cast<Expression>(user);
				collectPointers(allUses, expr->uses_begin(), expr->uses_end());
			}
		}
	}
	
	auto iter = statements.begin();
	if (iter == statements.end())
	{
		return nullptr;
	}
	
	SmallVector<NOT_NULL(Statement), 10> ancestry;
	getAncestry(ancestry, **iter);
	for (++iter; iter != statements.end(); ++iter)
	{
		SmallVector<NOT_NULL(Statement), 10> runningAncestry;
		getAncestry(runningAncestry, **iter);
		
		auto eraseFrom = mismatch(ancestry.begin(), ancestry.end(), runningAncestry.begin(), runningAncestry.end());
		ancestry.erase(eraseFrom.first, ancestry.end());
		if (ancestry.size() == 0)
		{
			return nullptr;
		}
	}
	
	return ancestry.back();
}

const ExpressionType& UnaryOperatorExpression::getExpressionType(AstContext &context) const
{
	const ExpressionType& operandType = getOperand()->getExpressionType(context);
	switch (getType())
	{
		case Increment:
		case Decrement:
		case ArithmeticNegate:
		case LogicalNegate:
		case BinaryNegate:
			return operandType;
			
		case AddressOf:
			return context.getPointerTo(operandType);
			
		case Dereference:
			return cast<PointerExpressionType>(operandType).getNestedType();
			
		default:
			llvm_unreachable("don't know how to infer expression type");
	}
}

bool UnaryOperatorExpression::operator==(const Expression& that) const
{
	if (auto unaryThat = llvm::dyn_cast<UnaryOperatorExpression>(&that))
	if (unaryThat->type == type)
	{
		return *getOperand() == *unaryThat->getOperand();
	}
	return false;
}

const ExpressionType& NAryOperatorExpression::getExpressionType(AstContext &context) const
{
	switch (getType())
	{
		case Assign:
		case Multiply:
		case Divide:
		case Modulus:
		case Add:
		case Subtract:
		case ShiftLeft:
		case ShiftRight:
		case BitwiseAnd:
		case BitwiseOr:
		case BitwiseXor:
			return getOperand(0)->getExpressionType(context);
			
		case ShortCircuitAnd:
		case ShortCircuitOr:
		case ComparisonMin ... static_cast<NAryOperatorType>(ComparisonMax - 1):
			return context.getIntegerType(false, 1);
			
		default:
			llvm_unreachable("don't know how to infer expression type");
	}
}

bool NAryOperatorExpression::operator==(const Expression& that) const
{
	return defaultEqualityCheck(*this, that);
}

pair<ExpressionUser::UserType, const StructExpressionType*> MemberAccessExpression::createInitInfo(AstContext& ctx, const Expression &base)
{
	const ExpressionType& baseType = base.getExpressionType(ctx);
	if (auto ptrType = dyn_cast<PointerExpressionType>(&baseType))
	{
		return make_pair(ExpressionUser::PointerAccess, cast<StructExpressionType>(&ptrType->getNestedType()));
	}
	else
	{
		return make_pair(ExpressionUser::MemberAccess, cast<StructExpressionType>(&baseType));
	}
}


const std::string& MemberAccessExpression::getFieldName() const
{
	return structureType[fieldIndex].name;
}

const ExpressionType& MemberAccessExpression::getExpressionType(AstContext&) const
{
	return structureType[fieldIndex].type;
}

bool MemberAccessExpression::operator==(const Expression &that) const
{
	if (defaultEqualityCheck(*this, that))
	{
		const auto& thatAccess = cast<MemberAccessExpression>(that);
		return thatAccess.fieldIndex == fieldIndex && &thatAccess.structureType == &structureType;
	}
	return false;
}

const ExpressionType& TernaryExpression::getExpressionType(AstContext &context) const
{
	return getTrueValue()->getExpressionType(context);
}

bool TernaryExpression::operator==(const Expression& that) const
{
	return defaultEqualityCheck(*this, that);
}

bool NumericExpression::operator==(const Expression& that) const
{
	if (auto token = llvm::dyn_cast<NumericExpression>(&that))
	{
		return this->ui64 == token->ui64;
	}
	return false;
}


TokenExpression::TokenExpression(AstContext& ctx, unsigned uses, const ExpressionType& type, llvm::StringRef token)
: Expression(Token, ctx, uses), expressionType(type), token(ctx.getPool().copyString(token))
{
	assert(uses == 0);
	assert(token.size() > 0 && token[0] != '\0');
}

bool TokenExpression::operator==(const Expression& that) const
{
	if (auto token = llvm::dyn_cast<TokenExpression>(&that))
	{
		return strcmp(this->token, token->token) == 0;
	}
	return false;
}

const ExpressionType& CallExpression::getExpressionType(AstContext& ctx) const
{
	const auto& pointerType = cast<PointerExpressionType>(getCallee()->getExpressionType(ctx));
	const auto& functionType = cast<FunctionExpressionType>(pointerType.getNestedType());
	return functionType.getReturnType();
}

bool CallExpression::operator==(const Expression& that) const
{
	return defaultEqualityCheck(*this, that);
}

CallExpression::iterator CallExpression::params_begin()
{
	auto iter = operands_begin();
	++iter;
	return iter;
}

CallExpression::const_iterator CallExpression::params_begin() const
{
	auto iter = operands_begin();
	++iter;
	return iter;
}

bool CastExpression::operator==(const Expression& that) const
{
	return defaultEqualityCheck(*this, that);
}

bool AggregateExpression::operator==(const Expression& that) const
{
	return defaultEqualityCheck(*this, that);
}

AggregateExpression* AggregateExpression::copyWithNewItem(unsigned int index, NOT_NULL(Expression) expression)
{
	auto copy = ctx.aggregate(getExpressionType(ctx), operands_size());
	unsigned i = 0;
	for (ExpressionUse& use : operands())
	{
		copy->setOperand(i, i == index ? static_cast<Expression*>(expression) : use.getUse());
		++i;
	}
	return copy;
}

const ExpressionType& SubscriptExpression::getExpressionType(AstContext& context) const
{
	const ExpressionType* baseType = &getPointer()->getExpressionType(context);
	if (auto ptrType = dyn_cast<PointerExpressionType>(baseType))
	{
		return ptrType->getNestedType();
	}
	else if (auto arrayType = dyn_cast<ArrayExpressionType>(baseType))
	{
		return arrayType->getNestedType();
	}
	else
	{
		llvm_unreachable("don't know how to infer type");
	}
}

bool SubscriptExpression::operator==(const Expression& that) const
{
	return defaultEqualityCheck(*this, that);
}

AssemblyExpression::AssemblyExpression(AstContext& ctx, unsigned uses, const FunctionExpressionType& type, StringRef assembly)
: Expression(Assembly, ctx, uses)
, expressionType(ctx.getPointerTo(type))
, assembly(ctx.getPool().copyString(assembly))
{
	assert(uses == 0);
}

bool AssemblyExpression::operator==(const Expression& that) const
{
	if (auto thatAsm = dyn_cast<AssemblyExpression>(&that))
	{
		return strcmp(assembly, thatAsm->assembly) == 0;
	}
	return false;
}

AssignableExpression::AssignableExpression(AstContext& ctx, unsigned uses, const ExpressionType& type, StringRef prefix, bool addressable)
: Expression(Assignable, ctx, uses)
, expressionType(type)
, prefix(ctx.getPool().copyString(prefix))
, addressable(addressable)
{
	assert(uses == 0);
}

bool AssignableExpression::operator==(const Expression& that) const
{
	if (auto thatAssignable = dyn_cast<AssignableExpression>(&that))
	{
		return &expressionType == &thatAssignable->expressionType
			&& strcmp(prefix, thatAssignable->prefix) == 0;
	}
	return false;
}
