//
// expression_use.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef use_list_hpp
#define use_list_hpp


#include <llvm/ADT/iterator_range.h>
#include <llvm/ADT/PointerIntPair.h>
#include <llvm/Support/raw_ostream.h>

#include <iterator>
#include <utility>

class Expression;
class ExpressionUse;
class ExpressionUser;

class ExpressionUse
{
	llvm::PointerIntPair<ExpressionUse*, 2, unsigned> prev;
	ExpressionUse* next;
	Expression* expression;
	
	void setPrevNext(ExpressionUse* use);
	void setNextPrev(ExpressionUse* use);
	
	std::pair<ExpressionUse*, size_t> walkWay();
	std::pair<ExpressionUse*, ExpressionUser*> walkToEndOfArray();
	
public:
	// borrowed from LLVM's Use
	enum PrevTag
	{
		Zero,
		One,
		Stop,
		FullStop
	};
	
	ExpressionUse(PrevTag tag)
	: prev(nullptr), next(nullptr), expression(nullptr)
	{
		prev.setInt(tag);
	}
	
	ExpressionUse* getPrev() { return prev.getPointer(); }
	const ExpressionUse* getPrev() const { return prev.getPointer(); }
	ExpressionUse* getNext() { return next; }
	const ExpressionUse* getNext() const { return next; }
	
	ExpressionUser* getUser();
	const ExpressionUser* getUser() const { return const_cast<ExpressionUse*>(this)->getUser(); }
	
	Expression* getUse() { return expression; }
	const Expression* getUse() const { return expression; }
	void setUse(Expression* target);
	
	operator Expression*() { return getUse(); }
	operator const Expression*() const { return getUse(); }
};

#endif /* use_list_hpp */
