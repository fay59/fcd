//
// expression_use.h
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

#ifndef use_list_hpp
#define use_list_hpp

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/iterator_range.h>
#include <llvm/ADT/PointerIntPair.h>
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

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
