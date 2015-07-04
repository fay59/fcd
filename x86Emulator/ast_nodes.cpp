//
//  ast_nodes.cpp
//  x86Emulator
//
//  Created by Félix on 2015-07-03.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#include "ast_nodes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <iostream>
#include <string>

using namespace llvm;
using namespace std;

namespace
{
	template<typename T, size_t N>
	constexpr size_t countof(const T (&)[N])
	{
		return N;
	}
	
	inline string indent(unsigned times)
	{
		return string(times, '\t');
	}
	
	string unaryOperators[] = {
		[UnaryOperatorExpression::LogicalNegate] = "!",
	};
	
	string binaryOperators[] = {
		[BinaryOperatorExpression::ShortCircuitAnd] = "&&",
		[BinaryOperatorExpression::ShortCircuitOr] = "||",
	};
	
	static_assert(countof(unaryOperators) == UnaryOperatorExpression::Max, "Incorrect number of strings for unary operators");
	static_assert(countof(binaryOperators) == BinaryOperatorExpression::Max, "Incorrect number of strings for binary operators");
	
	constexpr char nl = '\n';
}

void Statement::dump() const
{
	raw_os_ostream rerr(cerr);
	print(rerr);
}

void ValueExpression::print(llvm::raw_ostream &os) const
{
	os << '(';
	value->printAsOperand(os);
	os << ')';
}

void UnaryOperatorExpression::print(llvm::raw_ostream &os) const
{
	os << (type < Max ? unaryOperators[type] : "<bad unary>");
	operand->print(os);
}

void BinaryOperatorExpression::print(llvm::raw_ostream &os) const
{
	left->print(os);
	os << ' ' << (type < Max ? binaryOperators[type] : "<bad binary>") << ' ';
	right->print(os);
}

void SequenceNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent) << '{' << nl;
	for (size_t i = 0; i < count; i++)
	{
		nodes[i]->print(os, indent + 1);
	}
	os << ::indent(indent) << '}' << nl;
}

void IfElseNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent) << "if ";
	condition->print(os);
	os << nl;
	
	ifBody->print(os, indent + !isa<SequenceNode>(ifBody));
	if (elseBody != nullptr)
	{
		os << ::indent(indent) << "else" << nl;
		elseBody->print(os, indent + !isa<SequenceNode>(elseBody));
	}
}

void ExpressionNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent);
	if (auto valueNode = dyn_cast<ValueExpression>(expression))
	{
		valueNode->value->print(os);
	}
	else
	{
		expression->print(os);
	}
	os << nl;
}
