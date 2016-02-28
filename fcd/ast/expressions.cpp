//
// expressions.cpp
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

#include "ast_context.h"
#include "expressions.h"
#include "function.h"
#include "statements.h"
#include "print.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <cstring>

using namespace llvm;
using namespace std;

bool Expression::defaultEqualityCheck(const Expression &a, const Expression &b)
{
	if (a.getUserType() == b.getUserType() && a.operands_size() == b.operands_size())
	{
		return std::equal(a.operands_begin(), a.operands_end(), b.operands_begin(), [](const Expression* a, const Expression* b)
		{
			return *a == *b;
		});
	}
	return false;
}

void Expression::print(raw_ostream& os) const
{
	errs() << "(missing)";
}

void Expression::dump() const
{
	print(errs());
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

bool NAryOperatorExpression::operator==(const Expression& that) const
{
	return defaultEqualityCheck(*this, that);
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


TokenExpression::TokenExpression(AstContext& ctx, unsigned uses, llvm::StringRef token)
: Expression(Token, ctx, uses), token(ctx.getPool().copyString(token))
{
	assert(uses == 0);
}

bool TokenExpression::operator==(const Expression& that) const
{
	if (auto token = llvm::dyn_cast<TokenExpression>(&that))
	{
		return strcmp(this->token, token->token) == 0;
	}
	return false;
}

bool CallExpression::operator==(const Expression& that) const
{
	return defaultEqualityCheck(*this, that);
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
	auto copy = ctx.aggregate(operands_size());
	unsigned i = 0;
	for (ExpressionUse& use : operands())
	{
		copy->setOperand(i, i == index ? static_cast<Expression*>(expression) : use.getUse());
		++i;
	}
	return copy;
}

bool SubscriptExpression::operator==(const Expression& that) const
{
	return defaultEqualityCheck(*this, that);
}

AssemblyExpression::AssemblyExpression(AstContext& ctx, unsigned uses, StringRef assembly)
: Expression(Assembly, ctx, uses)
, ctx(ctx)
, parameterNames(ctx.getPool())
, assembly(ctx.getPool().copyString(assembly))
{
	assert(uses == 0);
}

void AssemblyExpression::addParameterName(StringRef paramName)
{
	const char* copied = ctx.getPool().copyString(paramName);
	parameterNames.push_back(copied);
}

bool AssemblyExpression::operator==(const Expression& that) const
{
	if (auto thatAsm = dyn_cast<AssemblyExpression>(&that))
	{
		return strcmp(assembly, thatAsm->assembly) == 0;
	}
	return false;
}

AssignableExpression::AssignableExpression(AstContext& ctx, unsigned uses, NOT_NULL(TokenExpression) type, StringRef assembly)
: Expression(Assignable, ctx, uses)
, prefix(ctx.getPool().copyString(assembly))
{
	assert(uses == 1);
	setType(type);
}

bool AssignableExpression::operator==(const Expression& that) const
{
	if (auto thatAssignable = dyn_cast<AssignableExpression>(&that))
	{
		return *getType() == *thatAssignable->getType() && strcmp(prefix, thatAssignable->prefix) == 0;
	}
	return false;
}
