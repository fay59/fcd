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
	if (a.getUserType() == b.getUserType() && a.operands_size() == b.operands_size())
	{
		return std::equal(a.operands_begin(), a.operands_end(), b.operands_begin(), [](const Expression* a, const Expression* b)
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
