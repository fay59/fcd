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
		[UnaryOperatorExpression::AddressOf] = "&",
		[UnaryOperatorExpression::Dereference] = "*",
		[UnaryOperatorExpression::LogicalNegate] = "!",
		[NAryOperatorExpression::Assign] = "=",
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
		[NAryOperatorExpression::MemberAccess] = ".",
		[NAryOperatorExpression::PointerAccess] = "->",
	};
	
	unsigned operatorPrecedence[] = {
		[NAryOperatorExpression::MemberAccess] = 1,
		[NAryOperatorExpression::PointerAccess] = 1,
		[UnaryOperatorExpression::Increment] = 1,
		[UnaryOperatorExpression::Decrement] = 1,
		[UnaryOperatorExpression::AddressOf] = 2,
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
		[NAryOperatorExpression::Assign] = 13,
	};
	
	constexpr unsigned subscriptPrecedence = 1;
	constexpr unsigned callPrecedence = 1;
	constexpr unsigned castPrecedence = 2;
	constexpr unsigned ternaryPrecedence = 13;
	const string badOperator = "<bad>";
	
	static_assert(countof(operatorName) == NAryOperatorExpression::Max, "Incorrect number of operator name entries");
	static_assert(countof(operatorPrecedence) == NAryOperatorExpression::Max, "Incorrect number of operator precedence entries");
	
	inline bool needsParentheses(unsigned thisPrecedence, const Expression& expression)
	{
		if (auto asNAry = dyn_cast<NAryOperatorExpression>(&expression))
		{
			return operatorPrecedence[asNAry->getType()] > thisPrecedence;
		}
		else if (auto asUnary = dyn_cast<UnaryOperatorExpression>(&expression))
		{
			return operatorPrecedence[asUnary->getType()] > thisPrecedence;
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
void ExpressionPrintVisitor::printWithParentheses(unsigned int precedence, const Expression& expression)
{
	bool parenthesize = needsParentheses(precedence, expression);
	if (parenthesize) os << '(';
	visit(expression);
	if (parenthesize) os << ')';
}

void ExpressionPrintVisitor::visitUnaryOperator(const UnaryOperatorExpression& unary)
{
	unsigned precedence = numeric_limits<unsigned>::max();
	auto type = unary.getType();
	if (type > UnaryOperatorExpression::Min && type < UnaryOperatorExpression::Max)
	{
		os << operatorName[type];
		precedence = operatorPrecedence[type];
	}
	else
	{
		os << badOperator;
	}
	printWithParentheses(precedence, *unary.getOperand());
}

void ExpressionPrintVisitor::visitNAryOperator(const NAryOperatorExpression& nary)
{
	assert(nary.operands_size() > 0);
	
	const std::string* displayName = &badOperator;
	unsigned precedence = numeric_limits<unsigned>::max();
	auto type = nary.getType();
	if (type >= NAryOperatorExpression::Min && type < NAryOperatorExpression::Max)
	{
		displayName = &operatorName[type];
		precedence = operatorPrecedence[type];
	}
	
	auto iter = nary.operands_begin();
	printWithParentheses(precedence, *iter->getUse());
	++iter;
	
	bool surroundWithSpaces =
		type != NAryOperatorExpression::MemberAccess
		&& type != NAryOperatorExpression::PointerAccess;
	
	for (; iter != nary.operands_end(); ++iter)
	{
		if (surroundWithSpaces)
		{
			os << ' ';
		}
		os << *displayName;
		if (surroundWithSpaces)
		{
			os << ' ';
		}
		
		printWithParentheses(precedence, *iter->getUse());
	}
}

void ExpressionPrintVisitor::visitTernary(const TernaryExpression& ternary)
{
	printWithParentheses(ternaryPrecedence, *ternary.getCondition());
	os << " ? ";
	printWithParentheses(ternaryPrecedence, *ternary.getTrueValue());
	os << " : ";
	printWithParentheses(ternaryPrecedence, *ternary.getFalseValue());
}

void ExpressionPrintVisitor::visitNumeric(const NumericExpression& numeric)
{
	os << numeric.si64;
}

void ExpressionPrintVisitor::visitToken(const TokenExpression& token)
{
	os << token.token;
}

void ExpressionPrintVisitor::visitCall(const CallExpression& call)
{
	const PooledDeque<NOT_NULL(const char)>* parameterNames = nullptr;
	auto callTarget = call.getCallee();
	if (auto assembly = dyn_cast<AssemblyExpression>(callTarget))
	{
		parameterNames = &assembly->parameterNames;
	}
	
	printWithParentheses(callPrecedence, *callTarget);
	
	size_t paramIndex = 0;
	os << '(';
	auto iter = call.params_begin();
	auto end = call.params_end();
	if (iter != end)
	{
		if (parameterNames != nullptr)
		{
			os << (*parameterNames)[paramIndex] << '=';
			paramIndex++;
		}
		
		visit(*iter->getUse());
		for (++iter; iter != end; ++iter)
		{
			os << ", ";
			if (parameterNames != nullptr)
			{
				os << (*parameterNames)[paramIndex] << '=';
				paramIndex++;
			}
			visit(*iter->getUse());
		}
	}
	os << ')';
}

void ExpressionPrintVisitor::visitCast(const CastExpression& cast)
{
	os << '(';
	// Maybe we'll want to get rid of this once we have better type inference.
	if (cast.sign == CastExpression::SignExtend)
	{
		os << "__sext ";
	}
	else if (cast.sign == CastExpression::ZeroExtend)
	{
		os << "__zext ";
	}
	visit(*cast.getCastType());
	os << ')';
	printWithParentheses(castPrecedence, *cast.getCastValue());
}

void ExpressionPrintVisitor::visitAggregate(const AggregateExpression& aggregate)
{
	os << '{';
	size_t count = aggregate.operands_size();
	if (count > 0)
	{
		auto iter = aggregate.operands_begin();
		visit(*iter->getUse());
		for (++iter; iter != aggregate.operands_end(); ++iter)
		{
			os << ", ";
			visit(*iter->getUse());
		}
	}
	os << '}';
}

void ExpressionPrintVisitor::visitSubscript(const SubscriptExpression& subscript)
{
	printWithParentheses(subscriptPrecedence, *subscript.getPointer());
	os << '[';
	visit(*subscript.getIndex());
	os << ']';
}

void ExpressionPrintVisitor::visitAssembly(const AssemblyExpression& assembly)
{
	os << "(__asm \"" << assembly.assembly << "\")";
}

void ExpressionPrintVisitor::visitAssignable(const AssignableExpression &assignable)
{
	os << "«" << assignable.prefix << ':' << &assignable << "»";
}

#pragma mark - Statements
std::string StatementPrintVisitor::indent() const
{
	return string(indentCount, '\t');
}

void StatementPrintVisitor::printWithIndent(Statement& statement)
{
	unsigned amount = isa<SequenceStatement>(statement) ? 0 : 1;
	indentCount += amount;
	visit(statement);
	indentCount -= amount;
}

void StatementPrintVisitor::visitIfElse(const IfElseStatement& ifElse, const std::string &firstLineIndent)
{
	os << firstLineIndent << "if (";
	visit(*ifElse.getCondition());
	os << ")\n";
	
	printWithIndent(*ifElse.ifBody);
	if (auto elseBody = ifElse.elseBody)
	{
		os << indent() << "else";
		if (auto otherCase = dyn_cast<IfElseStatement>(elseBody))
		{
			visitIfElse(*otherCase, " ");
		}
		else
		{
			os << nl;
			printWithIndent(*elseBody);
		}
	}
}

void StatementPrintVisitor::visitSequence(const SequenceStatement& sequence)
{
	os << indent() << '{' << nl;
	++indentCount;
	for (Statement* child : sequence.statements)
	{
		visit(*child);
	}
	--indentCount;
	os << indent() << '}' << nl;
}

void StatementPrintVisitor::visitIfElse(const IfElseStatement& ifElse)
{
	visitIfElse(ifElse, indent());
}

void StatementPrintVisitor::visitLoop(const LoopStatement& loop)
{
	if (loop.position == LoopStatement::PreTested)
	{
		os << indent() << "while (";
		visit(*loop.getCondition());
		os << ")\n";
		printWithIndent(*loop.loopBody);
	}
	else
	{
		assert(loop.position == LoopStatement::PostTested);
		os << indent() << "do" << nl;
		printWithIndent(*loop.loopBody);
		os << indent() << "while (";
		visit(*loop.getCondition());
		os << ");\n";
	}
}

void StatementPrintVisitor::visitKeyword(const KeywordStatement& keyword)
{
	os << indent() << keyword.name;
	if (auto operand = keyword.getOperand())
	{
		os << ' ';
		visit(*operand);
	}
	os << ";\n";
}

void StatementPrintVisitor::visitExpr(const ExpressionStatement& expression)
{
	os << indent();
	visit(*expression.getExpression());
	os << ";\n";
}

void StatementPrintVisitor::visitAssignable(const AssignableExpression &expr)
{
	// there should be a special case here but this commit does not implement it
	expressionPrinter.visitAssignable(expr);
}
