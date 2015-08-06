//
// symbolic_expr.cpp
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

#include "symbolic_expr.h"

#include <iostream>
#include <vector>

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

namespace
{
	struct CollectedOperands
	{
		int64_t constant;
		vector<Expression*> plus;
		vector<Expression*> minus;
		
		CollectedOperands() : constant(0)
		{
		}
	};
	
	void collectExpressionOperands(Expression* x, CollectedOperands& into, bool positive)
	{
		if (auto bin = dyn_cast<AddExpression>(x))
		{
			collectExpressionOperands(bin->getLeft(), into, positive);
			collectExpressionOperands(bin->getRight(), into, positive);
		}
		else if (auto constant = dyn_cast<ConstantIntExpression>(x))
		{
			int64_t multiplier = positive ? 1 : -1;
			into.constant += constant->getValue() * multiplier;
		}
		else if (auto negate = dyn_cast<NegateExpression>(x))
		{
			collectExpressionOperands(negate->getNegated(), into, positive == false);
		}
		else
		{
			(positive ? into.plus : into.minus).push_back(x);
		}
	}
	
	CollectedOperands collectExpressionOperands(AddExpression* x)
	{
		CollectedOperands operands;
		collectExpressionOperands(x, operands, true);
		return operands;
	}
}

void Expression::dump() const
{
	raw_os_ostream rerr(cerr);
	print(rerr);
	rerr << '\n';
}

void LiveOnEntryExpression::print(llvm::raw_ostream& os) const
{
	os << "LiveOnEntry[" << registerName << "]";
}

void LoadExpression::print(llvm::raw_ostream& os) const
{
	os << "<load expression>";
}

void ConstantIntExpression::print(llvm::raw_ostream& os) const
{
	os << value;
}

void AddExpression::print(llvm::raw_ostream& os) const
{
	left->print(os);
	os << " + ";
	right->print(os);
}

void NegateExpression::print(llvm::raw_ostream& os) const
{
	os << "-(";
	negated->print(os);
	os << ')';
}

Expression* ExpressionContext::simplify(Expression* x)
{
	// only binary operator expressions can be simplified
	if (auto bin = dyn_cast<AddExpression>(x))
	{
		CollectedOperands operands = collectExpressionOperands(bin);
		Expression* root = nullptr;
		for (Expression* pos : operands.plus)
		{
			root = root == nullptr ? pos : pool.allocate<AddExpression>(root, pos);
		}
		
		for (Expression* neg : operands.minus)
		{
			Expression* negated = pool.allocate<NegateExpression>(neg);
			root = root == nullptr ? negated : pool.allocate<AddExpression>(root, negated);
		}
		
		if (operands.constant != 0)
		{
			Expression* constant = pool.allocate<ConstantIntExpression>(operands.constant);
			root = root == nullptr ? constant : pool.allocate<AddExpression>(root, constant);
		}
		return root;
	}
	
	return x;
}
