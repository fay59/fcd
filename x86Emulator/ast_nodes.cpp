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
		return string('\t', times);
	}
	
	string unaryOperators[] = {
		[UnaryOperatorNode::LogicalNegate] = "!",
	};
	
	string binaryOperators[] = {
		[BinaryOperatorNode::ShortCircuitAnd] = "&&",
		[BinaryOperatorNode::ShortCircuitOr] = "||",
	};
	
	static_assert(countof(unaryOperators) == UnaryOperatorNode::Max, "Incorrect number of strings for unary operators");
	static_assert(countof(binaryOperators) == BinaryOperatorNode::Max, "Incorrect number of strings for binary operators");
	
	constexpr char nl = '\n';
}

void AstNode::dump() const
{
	raw_os_ostream rerr(cerr);
	print(rerr);
}

void ValueNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent);
	value->print(os);
	os << nl;
}

void UnaryOperatorNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << (type < Max ? unaryOperators[type] : "<bad unary>");
	operand->print(os);
}

void BinaryOperatorNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	left->print(os);
	os << ' ' << (type < Max ? binaryOperators[type] : "<bad binary>") << ' ';
	right->print(os);
}

void SequenceNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	if (indent > 0)
	{
		os << ::indent(indent - 1);
	}
	os << '{' << nl;
	
	for (size_t i = 0; i < count; i++)
	{
		nodes[i]->print(os, indent + indent == 0);
	}
	
	if (indent > 0)
	{
		os << ::indent(indent - 1);
	}
	os << '}' << nl;
}

void IfElseNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent) << "if ";
	condition->print(os, 0);
	ifBody->print(os, indent);
	if (elseBody != nullptr)
	{
		os << ::indent(indent) << "else" << nl;
		elseBody->print(os, indent);
	}
}

void GotoNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent) << "goto ";
	target->printAsOperand(os);
	os << nl;
}
