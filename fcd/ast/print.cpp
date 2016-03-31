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

#include "expression_type.h"
#include "print.h"
#include "type_printer.h"

#include <cctype>
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
		[MemberAccessExpression::MemberAccess] = ".",
		[MemberAccessExpression::PointerAccess] = "->",
	};
	
	unsigned operatorPrecedence[] = {
		[MemberAccessExpression::MemberAccess] = 1,
		[MemberAccessExpression::PointerAccess] = 1,
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
	
	static_assert(countof(operatorName) == MemberAccessExpression::Max, "Incorrect number of operator name entries");
	static_assert(countof(operatorPrecedence) == MemberAccessExpression::Max, "Incorrect number of operator precedence entries");
	
	bool needsParentheses(unsigned thisPrecedence, const Expression& expression)
	{
		if (auto asNAry = dyn_cast<NAryOperatorExpression>(&expression))
		{
			return operatorPrecedence[asNAry->getType()] > thisPrecedence;
		}
		else if (auto asUnary = dyn_cast<UnaryOperatorExpression>(&expression))
		{
			return operatorPrecedence[asUnary->getType()] > thisPrecedence;
		}
		else if (auto memberAccess = dyn_cast<MemberAccessExpression>(&expression))
		{
			return operatorPrecedence[memberAccess->getAccessType()] > thisPrecedence;
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
	
	bool shouldReduceIntoToken(const Expression& expr)
	{
		switch (expr.getUserType())
		{
			case Expression::Assignable:
				return true;
				
			case Expression::UnaryOperator:
			case Expression::Token:
			case Expression::Numeric:
			case Expression::Assembly:
				return false;
				
			case Expression::MemberAccess:
				return shouldReduceIntoToken(*cast<MemberAccessExpression>(expr).getBaseExpression());
				
			default:
				return expr.uses_many();
		}
	}
	
	string take(raw_string_ostream& os)
	{
		return move(os.str());
	}
}

const string* StatementPrintVisitor::getIdentifier(const Expression &expression)
{
	if (!tokenize || noTokens.count(&expression) != 0)
	{
		return nullptr;
	}
	
	if (!shouldReduceIntoToken(expression))
	{
		noTokens.insert(&expression);
		return nullptr;
	}
	
	auto iter = tokens.find(&expression);
	if (iter == tokens.end())
	{
		string& identifier = tokens[&expression];
		if (auto assignable = dyn_cast<AssignableExpression>(&expression))
		{
			raw_string_ostream(identifier) << assignable->prefix << tokens.size();
		}
		else
		{
			visit(expression);
			string lineValue = move(os.str());
			
			raw_string_ostream(identifier) << "anon" << tokens.size();
			
			os << identifier << " = " << lineValue << ';';
			currentScope->appendItem(os.str().c_str());
		}
		
		return &identifier;
	}
	else if (!iter->second.empty())
	{
		return &iter->second;
	}
	else
	{
		return nullptr;
	}
}

void StatementPrintVisitor::printWithParentheses(unsigned int precedence, const Expression& expression)
{
	visit(expression);
	
	if (needsParentheses(precedence, expression) && tokens.find(&expression) == tokens.end())
	{
		string expressionValue = move(os.str());
		os << '(' << expressionValue << ')';
	}
}

StatementPrintVisitor::StatementPrintVisitor(AstContext& ctx, llvm::raw_ostream& os, unsigned initialIndent, bool tokenize)
: ctx(ctx), tokenize(tokenize), currentValue(), os(currentValue)
{
	currentScope.reset(new PrintableScope(ctx.getPool(), nullptr));
}

StatementPrintVisitor::~StatementPrintVisitor()
{
}

void StatementPrintVisitor::visit(const ExpressionUser &user)
{
	if (auto expr = dyn_cast<Expression>(&user))
	if (auto id = getIdentifier(*expr))
	{
		os << *id;
		return;
	}
	
	AstVisitor::visit(user);
}

#pragma mark - Expressions
void StatementPrintVisitor::visitUnaryOperator(const UnaryOperatorExpression& unary)
{
	unsigned precedence;
	const char* operatorRepr;
	
	auto type = unary.getType();
	if (type > UnaryOperatorExpression::Min && type < UnaryOperatorExpression::Max)
	{
		operatorRepr = operatorName[type].c_str();
		precedence = operatorPrecedence[type];
	}
	else
	{
		operatorRepr = badOperator.c_str();
		precedence = numeric_limits<unsigned>::max();
	}
	
	printWithParentheses(precedence, *unary.getOperand());
	string value = take(os);
	os << operatorRepr << value;
}

void StatementPrintVisitor::visitNAryOperator(const NAryOperatorExpression& nary)
{
	assert(nary.operands_size() > 0);

	const string* displayName = &badOperator;
	unsigned precedence = numeric_limits<unsigned>::max();
	auto type = nary.getType();
	if (type >= NAryOperatorExpression::Min && type < NAryOperatorExpression::Max)
	{
		displayName = &operatorName[type];
		precedence = operatorPrecedence[type];
	}
	
	string result;
	raw_string_ostream outSS(result);
	
	auto iter = nary.operands_begin();
	printWithParentheses(precedence, *iter->getUse());
	++iter;
	
	outSS << take(os);
	for (; iter != nary.operands_end(); ++iter)
	{
		outSS << ' ' << *displayName << ' ';
		printWithParentheses(precedence, *iter->getUse());
		outSS << take(os);
	}
	swap(outSS.str(), os.str());
}

void StatementPrintVisitor::visitMemberAccess(const MemberAccessExpression &assignable)
{
	printWithParentheses(operatorPrecedence[assignable.getAccessType()], *assignable.getBaseExpression());
	os << operatorName[assignable.getAccessType()] << assignable.getFieldName();
}

void StatementPrintVisitor::visitTernary(const TernaryExpression& ternary)
{
	string result;
	raw_string_ostream outSS(result);
	
	printWithParentheses(ternaryPrecedence, *ternary.getCondition());
	outSS << take(os) << " ? ";
	printWithParentheses(ternaryPrecedence, *ternary.getTrueValue());
	outSS << take(os) << " : ";
	printWithParentheses(ternaryPrecedence, *ternary.getFalseValue());
	outSS << take(os);
	swap(outSS.str(), os.str());
}

void StatementPrintVisitor::visitNumeric(const NumericExpression& numeric)
{
	os << numeric.si64;
}

void StatementPrintVisitor::visitToken(const TokenExpression& token)
{
	os << token.token;
}

void StatementPrintVisitor::visitCall(const CallExpression& call)
{
	auto callTarget = call.getCallee();
	printWithParentheses(callPrecedence, *callTarget);
	
	string result;
	raw_string_ostream outSS(result);
	outSS << take(os);
	
	const auto& funcPointerType = cast<PointerExpressionType>(callTarget->getExpressionType(ctx));
	const auto& funcType = cast<FunctionExpressionType>(funcPointerType.getNestedType());
	size_t paramIndex = 0;
	outSS << '(';
	auto iter = call.params_begin();
	auto end = call.params_end();
	if (iter != end)
	{
		const string& paramName = funcType[paramIndex].name;
		if (paramName != "")
		{
			outSS << paramName << '=';
			paramIndex++;
		}
		
		visit(*iter->getUse());
		outSS << take(os);
		for (++iter; iter != end; ++iter)
		{
			outSS << ", ";
			const string& paramName = funcType[paramIndex].name;
			if (paramName != "")
			{
				outSS << paramName << '=';
				paramIndex++;
			}
			visit(*iter->getUse());
			outSS << take(os);
		}
	}
	outSS << ')';
	swap(outSS.str(), os.str());
}

void StatementPrintVisitor::visitCast(const CastExpression& cast)
{
	printWithParentheses(castPrecedence, *cast.getCastValue());
	string expr = take(os);
	
	os << '(';
	// XXX: are __sext and __zext annotations relevant? they only mirror whether
	// there's a "u" or not in front of the integer type.
	if (auto intType = dyn_cast<IntegerExpressionType>(&cast.getExpressionType(ctx)))
	if (auto innerType = dyn_cast<IntegerExpressionType>(&cast.getCastValue()->getExpressionType(ctx)))
	if (innerType->getBits() < intType->getBits())
	{
		os << (intType->isSigned() ? "__sext " : "__zext ");
	}
	
	CTypePrinter::print(os, cast.getExpressionType(ctx));
	os << ')';
	os << expr;
}

void StatementPrintVisitor::visitAggregate(const AggregateExpression& aggregate)
{
	string result;
	raw_string_ostream outSS(result);
	
	outSS << '{';
	size_t count = aggregate.operands_size();
	if (count > 0)
	{
		auto iter = aggregate.operands_begin();
		visit(*iter->getUse());
		outSS << take(os);
		
		for (++iter; iter != aggregate.operands_end(); ++iter)
		{
			outSS << ", ";
			visit(*iter->getUse());
			outSS << take(os);
		}
	}
	outSS << '}';
	swap(outSS.str(), os.str());
}

void StatementPrintVisitor::visitSubscript(const SubscriptExpression& subscript)
{
	visit(*subscript.getIndex());
	string index = take(os);
	
	printWithParentheses(subscriptPrecedence, *subscript.getPointer());
	string base = take(os);
	os << base << '[' << index << ']';
}

void StatementPrintVisitor::visitAssembly(const AssemblyExpression& assembly)
{
	os << "(__asm \"" << assembly.assembly << "\")";
}

void StatementPrintVisitor::visitAssignable(const AssignableExpression &assignable)
{
	// This is only executed when getIdentifier didn't return something
	// and this only happens when tokenization is disabled.
	os << "«" << assignable.prefix << ":" << &assignable << "»";
}

#pragma mark - Statements
void StatementPrintVisitor::print(AstContext& ctx, llvm::raw_ostream &os, const ExpressionUser& user, unsigned initialIndent, bool tokenize)
{
	StatementPrintVisitor printer(ctx, os, initialIndent, tokenize);
	printer.visit(user);
}

void StatementPrintVisitor::declare(raw_ostream& os, const ExpressionType &type, const string &variable)
{
	CTypePrinter::declare(os, type, variable);
}

void StatementPrintVisitor::visitNoop(const NoopStatement &noop)
{
}

void StatementPrintVisitor::visitSequence(const SequenceStatement& sequence)
{
	for (Statement* child : sequence)
	{
		visit(*child);
	}
}

void StatementPrintVisitor::visitIfElse(const IfElseStatement& ifElse)
{
	string prefix;
	raw_string_ostream outSS(prefix);
	
	const Statement* nextStatement = &ifElse;
	while (const auto nextIfElse = dyn_cast_or_null<IfElseStatement>(nextStatement))
	{
		visit(*ifElse.getCondition());
		outSS << "if (" << take(os) << ')';
		
		auto scope = std::make_unique<PrintableScope>(ctx.getPool(), currentScope.get());
		scope->setPrefix(take(outSS).c_str());
		
		swap(scope, currentScope);
		visit(*ifElse.getIfBody());
		swap(scope, currentScope);
		
		outSS << "else ";
		nextStatement = nextIfElse->getElseBody();
	}
	
	if (nextStatement != nullptr)
	{
		auto scope = std::make_unique<PrintableScope>(ctx.getPool(), currentScope.get());
		scope->setPrefix(take(outSS).c_str());
		
		swap(scope, currentScope);
		visit(*nextStatement);
		swap(scope, currentScope);
	}
}

void StatementPrintVisitor::visitLoop(const LoopStatement& loop)
{
	string prefix;
	raw_string_ostream outSS(prefix);
	auto scope = std::make_unique<PrintableScope>(ctx.getPool(), currentScope.get());
	
	if (loop.getPosition() == LoopStatement::PreTested)
	{
		visit(*loop.getCondition());
		outSS << "while (" << take(os) << ')';
		scope->setPrefix(take(outSS).c_str());
	}
	else
	{
		assert(loop.getPosition() == LoopStatement::PostTested);
		
		visit(*loop.getCondition());
		outSS << "while (" << take(os) << ");";
		scope->setPrefix("do");
		scope->setSuffix(take(outSS).c_str());
	}
	
	swap(scope, currentScope);
	visit(*loop.getLoopBody());
	swap(scope, currentScope);
}

void StatementPrintVisitor::visitKeyword(const KeywordStatement& keyword)
{
	string prefix;
	raw_string_ostream outSS(prefix);
	outSS << keyword.name;
	
	if (auto operand = keyword.getOperand())
	{
		visit(*operand);
		outSS << ' ' << take(os);
	}
	outSS << ';';
	currentScope->appendItem(take(outSS).c_str());
}

void StatementPrintVisitor::visitExpr(const ExpressionStatement& expression)
{
	const Expression& expr = *expression.getExpression();
	visit(expr);
	
	// Only print something if the expression wasn't turned into a token.
	if (tokens.find(&expr) != tokens.end())
	{
		os << ';';
		currentScope->appendItem(take(os).c_str());
	}
}
