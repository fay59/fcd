//
// ast_nodes.cpp
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

#include "ast_nodes.h"
#include "ast_function.h"

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
	
	constexpr unsigned callPrecedence = 1;
	constexpr unsigned castPrecedence = 2;
	constexpr unsigned ternaryPrecedence = 13;
	
	static_assert(countof(operatorName) == NAryOperatorExpression::Max, "Incorrect number of operator name entries");
	static_assert(countof(operatorPrecedence) == NAryOperatorExpression::Max, "Incorrect number of operator precedence entries");
	
	inline bool needsParentheses(unsigned thisPrecedence, Expression* expression)
	{
		if (auto asNAry = dyn_cast<NAryOperatorExpression>(expression))
		{
			return operatorPrecedence[asNAry->type] > thisPrecedence;
		}
		else if (auto asUnary = dyn_cast<UnaryOperatorExpression>(expression))
		{
			return operatorPrecedence[asUnary->type] > thisPrecedence;
		}
		else if (isa<CastExpression>(expression))
		{
			return castPrecedence > thisPrecedence;
		}
		else if (isa<TernaryExpression>(expression))
		{
			return ternaryPrecedence > thisPrecedence;
		}
		return false;
	}
	
	template<typename TPrint>
	void withParentheses(unsigned thisPrecedence, Expression* expression, llvm::raw_ostream& os, TPrint&& print)
	{
		bool parenthesize = needsParentheses(thisPrecedence, expression);
		if (parenthesize) os << '(';
		print();
		if (parenthesize) os << ')';
	}
	
	constexpr char nl = '\n';
	
	KeywordNode breakNode("break");
	TokenExpression trueExpression("true");
	TokenExpression falseExpression("false");
	TokenExpression undefExpression("__undefined");
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

void SequenceNode::printShort(llvm::raw_ostream& os) const
{
	os << "{ ... }";
}

void IfElseNode::print(llvm::raw_ostream &os, unsigned int indent, const std::string& firstLineIndent) const
{
	os << firstLineIndent;
	printShort(os);
	os << nl;
	
	ifBody->print(os, indent + !isa<SequenceNode>(ifBody));
	if (elseBody != nullptr)
	{
		os << ::indent(indent) << "else";
		if (auto ifElse = dyn_cast<IfElseNode>(elseBody))
		{
			ifElse->print(os, indent, " ");
		}
		else
		{
			os << nl;
			elseBody->print(os, indent + !isa<SequenceNode>(elseBody));
		}
	}
}

void IfElseNode::printShort(llvm::raw_ostream& os) const
{
	os << "if (";
	condition->print(os);
	os << ')';
}

void IfElseNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	print(os, indent, ::indent(indent));
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
		os << ");\n";
	}
}

void LoopNode::printShort(llvm::raw_ostream& os) const
{
	if (position == PreTested)
	{
		os << "while (";
		condition->print(os);
		os << ')';
	}
	else
	{
		os << "do { ... } while (";
		condition->print(os);
		os << ')';
	}
}

KeywordNode* KeywordNode::breakNode = &::breakNode;

void KeywordNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent);
	printShort(os);
	os << nl;
}

void KeywordNode::printShort(llvm::raw_ostream &os) const
{
	os << name;
	if (operand != nullptr)
	{
		os << ' ';
		operand->print(os);
	}
	os << ';';
}

void ExpressionNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent);
	expression->print(os);
	os << ';' << nl;
}

void ExpressionNode::printShort(llvm::raw_ostream &os) const
{
	expression->print(os);
}

void DeclarationNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent);
	printShort(os);
	os << ';';
	if (comment != nullptr)
	{
		os << " // " << comment;
	}
	os << nl;
}

void DeclarationNode::printShort(llvm::raw_ostream &os) const
{
	type->print(os);
	os << ' ';
	name->print(os);
}

void AssignmentNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent);
	printShort(os);
	os << ';' << nl;
}

void AssignmentNode::printShort(llvm::raw_ostream& os) const
{
	left->print(os);
	os << " = ";
	right->print(os);
}

#pragma mark - Expressions

void UnaryOperatorExpression::print(llvm::raw_ostream &os) const
{
	os << (type < Max ? operatorName[type] : "<bad unary>");
	withParentheses(operatorPrecedence[type], operand, os, [&]()
	{
		operand->print(os);
	});
}

bool UnaryOperatorExpression::isReferenceEqual(const Expression *that) const
{
	if (auto unaryThat = llvm::dyn_cast<UnaryOperatorExpression>(that))
		if (unaryThat->type == type)
		{
			return operand->isReferenceEqual(unaryThat->operand);
		}
	return false;
}

void NAryOperatorExpression::addOperand(Expression *expression)
{
	if (auto asNAry = dyn_cast<NAryOperatorExpression>(expression))
	if (asNAry->type == type)
	{
		operands.push_back(asNAry->operands.begin(), asNAry->operands.end());
		return;
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
	withParentheses(operatorPrecedence[type], expr, os, [&]()
	{
		expr->print(os);
	});
}

bool NAryOperatorExpression::isReferenceEqual(const Expression *that) const
{
	if (auto naryThat = llvm::dyn_cast<NAryOperatorExpression>(that))
	if (naryThat->type == type)
	{
		return std::equal(operands.cbegin(), operands.cend(), naryThat->operands.cbegin(), [](const Expression* a, const Expression* b)
		{
			return a->isReferenceEqual(b);
		});
	}
	return false;
}

void TernaryExpression::print(llvm::raw_ostream& os) const
{
	withParentheses(ternaryPrecedence, condition, os, [&]()
	{
		condition->print(os);
	});
	
	os << " ? ";
	
	withParentheses(ternaryPrecedence, ifTrue, os, [&]()
	{
		ifTrue->print(os);
	});
	
	os << " : ";
	
	withParentheses(ternaryPrecedence, ifFalse, os, [&]()
	{
		ifFalse->print(os);
	});
}

bool TernaryExpression::isReferenceEqual(const Expression *that) const
{
	if (auto ternary = llvm::dyn_cast<TernaryExpression>(that))
	{
		return ifTrue->isReferenceEqual(ternary->ifTrue) && ifFalse->isReferenceEqual(ternary->ifFalse);
	}
	return false;
}

void NumericExpression::print(llvm::raw_ostream& os) const
{
	os << ui64;
}

bool NumericExpression::isReferenceEqual(const Expression *that) const
{
	if (auto token = llvm::dyn_cast<NumericExpression>(that))
	{
		return this->ui64 == token->ui64;
	}
	return false;
}

TokenExpression* TokenExpression::trueExpression = &::trueExpression;
TokenExpression* TokenExpression::falseExpression = &::falseExpression;
TokenExpression* TokenExpression::undefExpression = &::undefExpression;

void TokenExpression::print(llvm::raw_ostream &os) const
{
	os << token;
}

bool TokenExpression::isReferenceEqual(const Expression *that) const
{
	if (auto token = llvm::dyn_cast<TokenExpression>(that))
	{
		return strcmp(this->token, token->token) == 0;
	}
	return false;
}

void CallExpression::print(llvm::raw_ostream& os) const
{
	withParentheses(callPrecedence, callee, os, [&]()
	{
		callee->print(os);
	});
	
	os << '(';
	auto iter = parameters.begin();
	auto end = parameters.end();
	if (iter != end)
	{
		(*iter)->print(os);
		++iter;
		while (iter != end)
		{
			os << ", ";
			(*iter)->print(os);
			++iter;
		}
	}
	os << ')';
}

bool CallExpression::isReferenceEqual(const Expression *that) const
{
	if (auto thatCall = llvm::dyn_cast<CallExpression>(that))
	if (this->callee == thatCall->callee)
	{
		return std::equal(parameters.begin(), parameters.end(), thatCall->parameters.begin(), [](Expression* a, Expression* b)
		{
			return a->isReferenceEqual(b);
		});
	}
	return false;
}

void CastExpression::print(llvm::raw_ostream& os) const
{
	os << '(';
	type->print(os);
	os << ')';
	
	withParentheses(castPrecedence, casted, os, [&]()
	{
		casted->print(os);
	});
}

bool CastExpression::isReferenceEqual(const Expression *that) const
{
	if (auto thatCast = llvm::dyn_cast<CastExpression>(that))
	{
		return type->isReferenceEqual(thatCast->type) && casted->isReferenceEqual(thatCast->casted);
	}
	return false;
}
