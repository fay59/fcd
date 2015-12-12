//
// print.cpp
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

#include "print.h"

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
	
	constexpr unsigned subscriptPrecedence = 1;
	constexpr unsigned callPrecedence = 1;
	constexpr unsigned castPrecedence = 2;
	constexpr unsigned ternaryPrecedence = 13;
	const string badOperator = "<bad>";
	
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
	
	constexpr char nl = '\n';
}

#pragma mark - Expressions
void ExpressionPrintVisitor::printWithParentheses(unsigned int precedence, Expression *expression)
{
	bool parenthesize = needsParentheses(precedence, expression);
	if (parenthesize) os << '(';
	expression->visit(*this);
	if (parenthesize) os << ')';
}

void ExpressionPrintVisitor::visitUnary(UnaryOperatorExpression* unary)
{
	unsigned precedence = numeric_limits<unsigned>::max();
	if (unary->type > UnaryOperatorExpression::Min && unary->type < UnaryOperatorExpression::Max)
	{
		os << operatorName[unary->type];
		precedence = operatorPrecedence[unary->type];
	}
	else
	{
		os << badOperator;
	}
	printWithParentheses(precedence, unary->operand);
}

void ExpressionPrintVisitor::visitNAry(NAryOperatorExpression* nary)
{
	assert(nary->operands.size() > 0);
	
	const std::string* displayName = &badOperator;
	unsigned precedence = numeric_limits<unsigned>::max();
	if (nary->type >= NAryOperatorExpression::Min && nary->type < NAryOperatorExpression::Max)
	{
		displayName = &operatorName[nary->type];
		precedence = operatorPrecedence[nary->type];
	}
	
	auto iter = nary->operands.begin();
	printWithParentheses(precedence, *iter);
	++iter;
	for (; iter != nary->operands.end(); ++iter)
	{
		os << ' ' << *displayName << ' ';
		printWithParentheses(precedence, *iter);
	}
}

void ExpressionPrintVisitor::visitTernary(TernaryExpression* ternary)
{
	printWithParentheses(ternaryPrecedence, ternary->condition);
	os << " ? ";
	printWithParentheses(ternaryPrecedence, ternary->ifTrue);
	os << " : ";
	printWithParentheses(ternaryPrecedence, ternary->ifFalse);
}

void ExpressionPrintVisitor::visitNumeric(NumericExpression* numeric)
{
	os << numeric->si64;
}

void ExpressionPrintVisitor::visitToken(TokenExpression* token)
{
	os << token->token;
}

void ExpressionPrintVisitor::visitCall(CallExpression* call)
{
	printWithParentheses(callPrecedence, call->callee);
	os << '(';
	auto iter = call->parameters.begin();
	auto end = call->parameters.end();
	if (iter != end)
	{
		(*iter)->visit(*this);
		for (++iter; iter != end; ++iter)
		{
			os << ", ";
			(*iter)->visit(*this);
		}
	}
	os << ')';
}

void ExpressionPrintVisitor::visitCast(CastExpression* cast)
{
	os << '(';
	// Maybe we'll want to get rid of this once we have better type inference.
	if (cast->sign == CastExpression::SignExtend)
	{
		os << "__sext ";
	}
	else if (cast->sign == CastExpression::ZeroExtend)
	{
		os << "__zext ";
	}
	cast->type->visit(*this);
	os << ')';
	printWithParentheses(castPrecedence, cast->casted);
}

void ExpressionPrintVisitor::visitAggregate(AggregateExpression* cast)
{
	os << '{';
	size_t count = cast->values.size();
	if (count > 0)
	{
		cast->values[0]->visit(*this);
		for (size_t i = 1; i < count; ++i)
		{
			os << ", ";
			cast->values[i]->visit(*this);
		}
	}
	os << '}';
}

void ExpressionPrintVisitor::visitSubscript(SubscriptExpression *subscript)
{
	printWithParentheses(subscriptPrecedence, subscript->left);
	os << '[' << subscript->index << ']';
}

#pragma mark - Statements
std::string StatementPrintVisitor::indent() const
{
	return string(indentCount, '\t');
}

void StatementPrintVisitor::printWithIndent(Statement *statement)
{
	unsigned amount = isa<SequenceStatement>(statement) ? 0 : 1;
	indentCount += amount;
	statement->visit(*this);
	indentCount -= amount;
}

void StatementPrintVisitor::visitIfElse(IfElseStatement *ifElse, const std::string &firstLineIndent)
{
	os << firstLineIndent << "if (";
	ifElse->condition->visit(expressionPrinter);
	os << ")\n";
	
	printWithIndent(ifElse->ifBody);
	if (auto elseBody = ifElse->elseBody)
	{
		os << indent() << "else";
		if (auto otherCase = dyn_cast<IfElseStatement>(elseBody))
		{
			visitIfElse(otherCase, " ");
		}
		else
		{
			os << nl;
			printWithIndent(elseBody);
		}
	}
}

void StatementPrintVisitor::visitSequence(SequenceStatement* sequence)
{
	os << indent() << '{' << nl;
	++indentCount;
	StatementVisitor::visitSequence(sequence);
	--indentCount;
	os << indent() << '}' << nl;
}

void StatementPrintVisitor::visitIfElse(IfElseStatement* ifElse)
{
	visitIfElse(ifElse, indent());
}

void StatementPrintVisitor::visitLoop(LoopStatement* loop)
{
	if (loop->position == LoopStatement::PreTested)
	{
		os << indent() << "while (";
		loop->condition->visit(expressionPrinter);
		os << ")\n";
		printWithIndent(loop->loopBody);
	}
	else
	{
		assert(loop->position == LoopStatement::PostTested);
		os << indent() << "do" << nl;
		printWithIndent(loop->loopBody);
		os << indent() << "while (";
		loop->condition->visit(expressionPrinter);
		os << ");\n";
	}
}

void StatementPrintVisitor::visitKeyword(KeywordStatement* keyword)
{
	os << indent() << keyword->name;
	if (auto operand = keyword->operand)
	{
		os << ' ';
		operand->visit(expressionPrinter);
	}
	os << ";\n";
}

void StatementPrintVisitor::visitExpression(ExpressionStatement* expression)
{
	os << indent();
	expression->expression->visit(expressionPrinter);
	os << ";\n";
}

void StatementPrintVisitor::visitDeclaration(DeclarationStatement* declaration)
{
	os << indent();
	declaration->type->visit(expressionPrinter);
	os << ' ';
	declaration->name->visit(expressionPrinter);
	os << ';';
	if (auto comment = declaration->comment)
	{
		os << " // " << comment;
	}
	os << nl;
}

void StatementPrintVisitor::visitAssignment(AssignmentStatement* assignment)
{
	os << indent();
	assignment->left->visit(expressionPrinter);
	os << " = ";
	assignment->right->visit(expressionPrinter);
	os << ";\n";
}

#pragma mark - Short Statements

void StatementShortPrintVisitor::visitSequence(SequenceStatement* sequence)
{
	os << "{ ... }";
}

void StatementShortPrintVisitor::visitIfElse(IfElseStatement *ifElse)
{
	os << "if (";
	ifElse->condition->visit(expressionPrinter);
	os << ')';
}

void StatementShortPrintVisitor::visitLoop(LoopStatement* loop)
{
	if (loop->position == LoopStatement::PreTested)
	{
		os << "while (";
		loop->condition->visit(expressionPrinter);
		os << ')';
	}
	else
	{
		assert(loop->position == LoopStatement::PostTested);
		os << "do while (";
		loop->condition->visit(expressionPrinter);
		os << ')';
	}
}

void StatementShortPrintVisitor::visitKeyword(KeywordStatement* keyword)
{
	os << keyword->name;
	if (auto operand = keyword->operand)
	{
		os << ' ';
		operand->visit(expressionPrinter);
	}
}

void StatementShortPrintVisitor::visitExpression(ExpressionStatement* expression)
{
	expression->expression->visit(expressionPrinter);
}

void StatementShortPrintVisitor::visitDeclaration(DeclarationStatement* declaration)
{
	declaration->type->visit(expressionPrinter);
	os << ' ';
	declaration->name->visit(expressionPrinter);
}

void StatementShortPrintVisitor::visitAssignment(AssignmentStatement* assignment)
{
	assignment->left->visit(expressionPrinter);
	os << " = ";
	assignment->right->visit(expressionPrinter);
}
