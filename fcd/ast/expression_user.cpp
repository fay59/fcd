//
// expression_user.cpp
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

void ExpressionUser::print(raw_ostream& os) const
{
	StatementPrintVisitor::print(os, *this, 0, false);
}

void ExpressionUser::dump() const
{
	print(errs());
}
