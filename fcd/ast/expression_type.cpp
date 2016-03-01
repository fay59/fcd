//
// expression_type.cpp
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

#include "expression_type.h"

using namespace std;
using namespace llvm;

namespace
{
	template<typename TIter>
	void printRange(raw_ostream& os, TIter begin, TIter end)
	{
		auto iter = begin;
		if (iter != end)
		{
			iter->type.print(os);
			os << ' ' << iter->name;
			for (++iter; iter != end; ++iter)
			{
				os << ", ";
				iter->type.print(os);
				os << ' ' << iter->name;
			}
		}
	}
}

void ExpressionType::dump() const
{
	print(errs());
}

void VoidExpressionType::print(llvm::raw_ostream& os) const
{
	os << "void";
}

void IntegerExpressionType::print(llvm::raw_ostream& os) const
{
	os << (hasSign ? "" : "u") << "int" << numBits << "_t";
}

void PointerExpressionType::print(llvm::raw_ostream& os) const
{
	nested.print(os);
	os << '*';
}

void ArrayExpressionType::print(llvm::raw_ostream& os) const
{
	nested.print(os);
	os << '[' << numElement << ']';
}

void StructExpressionType::print(llvm::raw_ostream& os) const
{
	os << '{';
	printRange(os, begin(), end());
	os << '}';
}

void FunctionExpressionType::print(llvm::raw_ostream& os) const
{
	returnType.print(os);
	os << '(';
	printRange(os, begin(), end());
	os << ')';
}
