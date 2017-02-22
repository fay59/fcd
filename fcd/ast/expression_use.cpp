//
// expression_use.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "expression_use.h"
#include "expressions.h"

using namespace llvm;
using namespace std;

void ExpressionUse::setPrevNext(ExpressionUse *use)
{
	if (auto pointer = prev.getPointer())
	{
		pointer->next = use;
	}
	else if (expression != nullptr)
	{
		expression->firstUse = use;
	}
}

void ExpressionUse::setNextPrev(ExpressionUse *use)
{
	if (auto pointer = next)
	{
		pointer->prev.setPointer(use);
	}
}

pair<ExpressionUse*, size_t> ExpressionUse::walkWay()
{
	size_t total = 0;
	ExpressionUse* current = this;
	while (current->prev.getInt() < Stop)
	{
		total <<= 1;
		total |= current->prev.getInt();
		++current;
	}
	return make_pair(current, total);
}

pair<ExpressionUse*, ExpressionUser*> ExpressionUse::walkToEndOfArray()
{
	ExpressionUse* stop;
	size_t skip;
	tie(stop, skip) = walkWay();
	
	if (stop->prev.getInt() == FullStop)
	{
		skip = 1;
	}
	else
	{
		tie(stop, skip) = stop[1].walkWay();
	}
	
	ExpressionUse* endPointer = &stop[skip];
	auto atLocation = reinterpret_cast<PointerIntPair<void*, 1>*>(endPointer);
	
	// Pointer heresy directly based off what LLVM does.
	// (http://llvm.org/docs/doxygen/html/Use_8cpp_source.html#l00041)
	if (atLocation->getInt() == 0)
	{
		// aligned pointer; this is not a tagged pointer
		// (we're reading the User vtable)
		return make_pair(nullptr, reinterpret_cast<ExpressionUser*>(atLocation));
	}
	else
	{
		// tagged pointer, hung-off uses; the pointer in atLocation points to the user
		return make_pair(nullptr, reinterpret_cast<ExpressionUser*>(atLocation->getPointer()));
	}
}

ExpressionUser* ExpressionUse::getUser()
{
	ExpressionUse* use = this;
	ExpressionUser* user = nullptr;
	while (user == nullptr)
	{
		tie(use, user) = use->walkToEndOfArray();
	}
	return user;
}

void ExpressionUse::setUse(Expression *target)
{
	if (expression == target)
	{
		return;
	}
	
	// unlink
	setPrevNext(next);
	setNextPrev(prev.getPointer());
	
	// link with new expression
	expression = target;
	if (expression == nullptr)
	{
		next = nullptr;
	}
	else
	{
		next = expression->firstUse;
		expression->firstUse = this;
	}
	prev.setPointer(nullptr);
	setNextPrev(this);
}
