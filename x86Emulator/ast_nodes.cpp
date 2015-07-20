//
//  ast_nodes.cpp
//  x86Emulator
//
//  Created by Félix on 2015-07-03.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#include "ast_nodes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Constants.h>
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <iostream>
#include <limits>
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
	
	inline string toString(size_t integer)
	{
		string result;
		raw_string_ostream(result) << integer;
		return result;
	}
	
	string operatorName[] = {
		[UnaryOperatorExpression::Increment] = "++",
		[UnaryOperatorExpression::Decrement] = "--",
		[UnaryOperatorExpression::Dereference] = "*",
		[UnaryOperatorExpression::LogicalNegate] = "!",
		[NAryOperatorExpression::Multiply] = "*",
		[NAryOperatorExpression::Divide] = "/",
		[NAryOperatorExpression::Modulus] = "%",
		[NAryOperatorExpression::Add] = "+",
		[NAryOperatorExpression::Subtract] = "-",
		[NAryOperatorExpression::ShiftLeft] = "<<",
		[NAryOperatorExpression::ShiftRight] = ">>",
		[NAryOperatorExpression::SmallerThan] = "<",
		[NAryOperatorExpression::SmallerOrEqualTo] = "<=",
		[NAryOperatorExpression::GreaterThan] = ">",
		[NAryOperatorExpression::GreaterOrEqualTo] = ">=",
		[NAryOperatorExpression::Equal] = "==",
		[NAryOperatorExpression::NotEqual] = "!=",
		[NAryOperatorExpression::BitwiseAnd] = "&",
		[NAryOperatorExpression::BitwiseXor] = "^",
		[NAryOperatorExpression::BitwiseOr] = "|",
		[NAryOperatorExpression::ShortCircuitAnd] = "&&",
		[NAryOperatorExpression::ShortCircuitOr] = "||",
	};
	
	unsigned operatorPrecedence[] = {
		[UnaryOperatorExpression::Increment] = 1,
		[UnaryOperatorExpression::Decrement] = 1,
		[UnaryOperatorExpression::Dereference] = 2,
		[UnaryOperatorExpression::LogicalNegate] = 2,
		[NAryOperatorExpression::Multiply] = 3,
		[NAryOperatorExpression::Divide] = 3,
		[NAryOperatorExpression::Modulus] = 3,
		[NAryOperatorExpression::Add] = 4,
		[NAryOperatorExpression::Subtract] = 4,
		[NAryOperatorExpression::ShiftLeft] = 5,
		[NAryOperatorExpression::ShiftRight] = 5,
		[NAryOperatorExpression::SmallerThan] = 6,
		[NAryOperatorExpression::SmallerOrEqualTo] = 6,
		[NAryOperatorExpression::GreaterThan] = 6,
		[NAryOperatorExpression::GreaterOrEqualTo] = 6,
		[NAryOperatorExpression::Equal] = 7,
		[NAryOperatorExpression::NotEqual] = 7,
		[NAryOperatorExpression::BitwiseAnd] = 8,
		[NAryOperatorExpression::BitwiseXor] = 9,
		[NAryOperatorExpression::BitwiseOr] = 10,
		[NAryOperatorExpression::ShortCircuitAnd] = 11,
		[NAryOperatorExpression::ShortCircuitOr] = 12,
	};
	
	static_assert(countof(operatorName) == NAryOperatorExpression::Max, "Incorrect number of operator name entries");
	static_assert(countof(operatorPrecedence) == NAryOperatorExpression::Max, "Incorrect number of operator precedence entries");
	
	constexpr char nl = '\n';
	
	KeywordNode breakNode("break");
	TokenExpression trueExpression("true");
	TokenExpression falseExpression("false");
}

#pragma mark - Statements

void Statement::dump() const
{
	raw_os_ostream rerr(cerr);
	print(rerr);
}

void SequenceNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent) << '{' << nl;
	for (size_t i = 0; i < statements.size(); i++)
	{
		statements[i]->print(os, indent + 1);
	}
	os << ::indent(indent) << '}' << nl;
}

void IfElseNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent) << "if (";
	condition->print(os);
	os << ")\n";
	
	ifBody->print(os, indent + !isa<SequenceNode>(ifBody));
	if (elseBody != nullptr)
	{
		os << ::indent(indent) << "else" << nl;
		elseBody->print(os, indent + !isa<SequenceNode>(elseBody));
	}
}

LoopNode::LoopNode(Statement* body)
: condition(TokenExpression::trueExpression), position(LoopNode::PreTested), loopBody(body)
{
}

void LoopNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	if (position == PreTested)
	{
		os << ::indent(indent) << "while (";
		condition->print(os);
		os << ")\n";
		loopBody->print(os, indent + !isa<SequenceNode>(loopBody));
	}
	else
	{
		assert(position == PostTested);
		os << ::indent(indent) << "do" << nl;
		loopBody->print(os, indent + !isa<SequenceNode>(loopBody));
		os << ::indent(indent) << "while (";
		condition->print(os);
		os << ")\n";
	}
}

KeywordNode* KeywordNode::breakNode = &::breakNode;

void KeywordNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent) << name;
	if (operand != nullptr)
	{
		os << ' ';
		operand->print(os);
	}
	os << ";" << nl;
}

void ExpressionNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent);
	expression->print(os);
	os << ';' << nl;
}

void DeclarationNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent);
	type->print(os);
	os << ' ';
	name->print(os);
	os << ';';
	if (comment != nullptr)
	{
		os << " // " << comment;
	}
	os << nl;
}

void AssignmentNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent);
	left->print(os);
	os << " = ";
	right->print(os);
	os << ';' << nl;
}

#pragma mark - Expressions

void UnaryOperatorExpression::print(llvm::raw_ostream &os) const
{
	bool parenthesize = false;
	if (auto nary = dyn_cast<NAryOperatorExpression>(operand))
	{
		parenthesize = operatorPrecedence[nary->type] > operatorPrecedence[type];
	}
	os << (type < Max ? operatorName[type] : "<bad unary>");
	if (parenthesize) os << '(';
	operand->print(os);
	if (parenthesize) os << ')';
}

void NAryOperatorExpression::addOperand(Expression *expression)
{
	if (auto asNAry = dyn_cast<NAryOperatorExpression>(expression))
	{
		if (asNAry->type == type)
		{
			operands.push_back(asNAry->operands.begin(), asNAry->operands.end());
			return;
		}
	}
	operands.push_back(expression);
}

void NAryOperatorExpression::print(llvm::raw_ostream &os) const
{
	assert(operands.size() > 0);
	
	auto iter = operands.begin();
	print(os, *iter);
	++iter;
	for (; iter != operands.end(); ++iter)
	{
		os << ' ' << (type < Max ? operatorName[type] : "<bad operator>") << ' ';
		print(os, *iter);
	}
}

void NAryOperatorExpression::print(raw_ostream& os, Expression* expr) const
{
	bool parenthesize = false;
	if (auto asNAry = dyn_cast<NAryOperatorExpression>(expr))
	{
		parenthesize = operatorPrecedence[asNAry->type] > operatorPrecedence[type];
	}
	else if (auto asUnary = dyn_cast<UnaryOperatorExpression>(expr))
	{
		parenthesize = operatorPrecedence[asUnary->type] > operatorPrecedence[type];
	}
	
	if (parenthesize) os << '(';
	expr->print(os);
	if (parenthesize) os << ')';
}

TokenExpression* TokenExpression::trueExpression = &::trueExpression;
TokenExpression* TokenExpression::falseExpression = &::falseExpression;

TokenExpression::TokenExpression(DumbAllocator& pool, size_t integralValue)
: TokenExpression(pool, toString(integralValue))
{
}

void TokenExpression::print(llvm::raw_ostream &os) const
{
	os << token;
}

void CallExpression::print(llvm::raw_ostream& os) const
{
	bool parenthesize = isa<NAryOperatorExpression>(callee) || isa<UnaryOperatorExpression>(callee);
	if (parenthesize) os << '(';
	callee->print(os);
	if (parenthesize) os << ')';
	
	os << '(';
	auto iter = parameters.begin();
	auto end = parameters.end();
	if (iter != end)
	{
		(*iter)->print(os);
		while (iter != end)
		{
			os << ", ";
			(*iter)->print(os);
			++iter;
		}
	}
	os << ')';
}
