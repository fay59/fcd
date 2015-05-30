//
//  symbolic_expr.cpp
//  x86Emulator
//
//  Created by Félix on 2015-05-29.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
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
			root = root == nullptr ? pos : allocate<AddExpression>(root, pos);
		}
		
		for (Expression* neg : operands.minus)
		{
			Expression* negated = allocate<NegateExpression>(neg);
			root = root == nullptr ? negated : allocate<AddExpression>(root, negated);
		}
		
		if (operands.constant != 0)
		{
			Expression* constant = allocate<ConstantIntExpression>(operands.constant);
			root = root == nullptr ? constant : allocate<AddExpression>(root, constant);
		}
		return root;
	}
	
	return x;
}
