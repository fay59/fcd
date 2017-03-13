//
// expression_user.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "expression_user.h"
#include "print.h"

using namespace llvm;
using namespace std;

namespace
{
	template<typename TAction>
	void iterateUseArrays(ExpressionUser* user, const ExpressionUseAllocInfo& allocatedAndUsed, TAction&& action)
	{
		auto arrayEnd = reinterpret_cast<ExpressionUse*>(user);
		unsigned allocated = allocatedAndUsed.allocated;
		unsigned used = allocatedAndUsed.used;
		auto arrayBegin = arrayEnd - allocated;
		while (arrayEnd != nullptr && action(arrayEnd - used, arrayEnd))
		{
			auto nextHead = &reinterpret_cast<ExpressionUseArrayHead*>(arrayBegin)[-1];
			used = nextHead->allocInfo.used;
			arrayBegin = nextHead->array;
			arrayEnd = arrayBegin == nullptr ? nullptr : arrayBegin + nextHead->allocInfo.allocated;
		}
	}
	
	template<typename TAction>
	void iterateUseArrays(const ExpressionUser* user, const ExpressionUseAllocInfo& allocatedAndUsed, TAction&& action)
	{
		auto arrayEnd = reinterpret_cast<const ExpressionUse*>(user);
		unsigned allocated = allocatedAndUsed.allocated;
		unsigned used = allocatedAndUsed.used;
		auto arrayBegin = arrayEnd - allocated;
		while (arrayEnd != nullptr && action(arrayEnd - used, arrayEnd))
		{
			auto nextHead = &reinterpret_cast<const ExpressionUseArrayHead*>(arrayBegin)[-1];
			used = nextHead->allocInfo.used;
			arrayBegin = nextHead->array;
			arrayEnd = arrayBegin == nullptr ? nullptr : arrayBegin + nextHead->allocInfo.allocated;
		}
	}
}

void ExpressionUser::anchor()
{
}

void ExpressionUser::dropAllExpressionReferences()
{
	for (ExpressionUse& use : operands())
	{
		if (auto expr = use.getUse())
		{
			use.setUse(nullptr);
			if (expr->uses_empty())
			{
				expr->dropAllReferences();
			}
		}
	}
}

void ExpressionUser::dropAllStatementReferences()
{
}

ExpressionUse& ExpressionUser::getOperandUse(unsigned int index)
{
	ExpressionUse* result = nullptr;
	iterateUseArrays(this, allocInfo, [&](ExpressionUse* begin, ExpressionUse* end)
	{
		ptrdiff_t count = end - begin;
		if (count >= index)
		{
			result = end - index - 1;
			return false;
		}
		else
		{
			index -= count;
			return true;
		}
	});
	
	return *result;
}

unsigned ExpressionUser::operands_size() const
{
	unsigned count = 0;
	iterateUseArrays(this, allocInfo, [&](const ExpressionUse* begin, const ExpressionUse* end)
	{
		count += end - begin;
		return true;
	});
	return count;
}

void ExpressionUser::dropAllReferences()
{
	dropAllExpressionReferences();
	dropAllStatementReferences();
}

void ExpressionUser::print(raw_ostream& os) const
{
	// This doesn't really need the AstContext used to create the statements.
	// However, I'd say that it's bad practice to create a whole new AstContext
	// just to use StatementPrintVisitor. I'd be unhappy to see that kind of code
	// outside of debug code.
	DumbAllocator pool;
	AstContext context(pool);
	StatementPrintVisitor::print(context, os, *this, false);
}

void ExpressionUser::dump() const
{
	print(errs());
}

ExpressionReference::ExpressionReference(std::nullptr_t)
: singleUse(ExpressionUse::FullStop), user(ExpressionUser::Temporary, 1, 1)
{
}

ExpressionReference::ExpressionReference(Expression* expr)
: ExpressionReference()
{
	user.setOperand(0, expr);
}

ExpressionReference::ExpressionReference(const ExpressionReference& that)
: ExpressionReference(that.get())
{
}

ExpressionReference::ExpressionReference(ExpressionReference&& that)
: ExpressionReference(that.get())
{
	that.reset();
}

ExpressionReference::~ExpressionReference()
{
	user.dropAllReferences();
}

ExpressionReference& ExpressionReference::operator=(Expression* expr)
{
	if (expr != get())
	{
		reset(expr);
	}
	return *this;
}

ExpressionReference& ExpressionReference::operator=(const ExpressionReference &that)
{
	if (that.get() != get())
	{
		reset(that.get());
	}
	return *this;
}

ExpressionReference& ExpressionReference::operator=(ExpressionReference&& that)
{
	if (that.get() != get())
	{
		reset(that.get());
	}
	that.reset();
	return *this;
}

void ExpressionReference::reset(Expression* expr)
{
	auto current = get();
	user.setOperand(0, expr);
	if (current != nullptr && current->uses_empty())
	{
		current->dropAllReferences();
	}
}
