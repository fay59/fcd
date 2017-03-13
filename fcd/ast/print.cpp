//
// print.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
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
		[UnaryOperatorExpression::ArithmeticNegate] = "-",
		[UnaryOperatorExpression::LogicalNegate] = "!",
		[UnaryOperatorExpression::BinaryNegate] = "~",
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
		[UnaryOperatorExpression::ArithmeticNegate] = 2,
		[UnaryOperatorExpression::LogicalNegate] = 2,
		[UnaryOperatorExpression::BinaryNegate] = 2,
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
			case Expression::MemberAccess:
				return false;
				
			case Expression::NAryOperator:
			{
				const auto& nary = cast<NAryOperatorExpression>(expr);
				bool isComparison = nary.getType() >= NAryOperatorExpression::ComparisonMin && nary.getType() < NAryOperatorExpression::ComparisonMax;
				return !isComparison && expr.uses_many();
			}
				
			default:
				return expr.uses_many();
		}
	}
	
	string take(raw_string_ostream& os)
	{
		return move(os.str());
	}
	
	template<typename TCollection>
	void getStatementParents(PrintableItem* statement, TCollection& ancestry)
	{
		ancestry.clear();
		for (auto parent = statement->getParent(); parent != nullptr; parent = parent->getParent())
		{
			ancestry.push_back(parent);
		}
		reverse(ancestry.begin(), ancestry.end());
	}
}

StatementPrintVisitor::Tokenization* StatementPrintVisitor::getIdentifier(const Expression &expression)
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
		auto insertResult = tokens.insert({&expression, {}});
		if (insertResult.second)
		{
			orderedTokens.push_back(&expression);
		}
		Tokenization& identifier = insertResult.first->second;
		size_t tokenId = tokens.size();
		if (auto assignable = dyn_cast<AssignableExpression>(&expression))
		{
			raw_string_ostream(identifier.token) << assignable->prefix << tokenId;
		}
		else
		{
			visit(expression);
			string lineValue = move(os.str());
			
			raw_string_ostream(identifier.token) << "anon" << tokenId;
			
			os << identifier.token << " = " << lineValue << ';';
			auto user = currentScope->appendItem(take(os).c_str());
			
			usedByStatement.push_back(&expression);
			fillUsers(user);
		}
		
		return &identifier;
	}
	else if (!iter->second.token.empty())
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

void StatementPrintVisitor::visit(PrintableScope* childScope, const StatementList& list)
{
	pushScope(childScope, [&] {
		visitAll(*this, list);
	});
	currentScope->appendItem(childScope);
}

void StatementPrintVisitor::fillUsers(PrintableItem* user)
{
	for (auto expression : usedByStatement)
	{
		auto insertResult = tokens.insert({expression, {}});
		if (insertResult.second)
		{
			orderedTokens.push_back(expression);
		}
		insertResult.first->second.users.push_back(user);
	}
	usedByStatement.clear();
}

void StatementPrintVisitor::insertDeclarations()
{
	for (const Expression* tokenKey : orderedTokens)
	{
		Tokenization& info = tokens.at(tokenKey);
		string& variable = info.token;
		
		// find first assignment to variable
		auto firstAssignment = info.users.begin();
		while (firstAssignment != info.users.end())
		{
			if (auto line = dyn_cast<PrintableLine>(*firstAssignment))
			{
				const char* lineData = line->getLine();
				auto iterPair = mismatch(variable.begin(), variable.end(), lineData);
				if (iterPair.first == variable.end() && strncmp(iterPair.second, " = ", 3) == 0)
				{
					// first assignment!
					break;
				}
			}
			++firstAssignment;
		}
		
		// then find common ancestor for all uses, going as far as the first assignment
		SmallVector<PrintableScope*, 10> parents;
		decltype(parents)::iterator onePastCommonAncestor;
		
		if (firstAssignment == info.users.end())
		{
			// this happens for values that are not assigned to, like alloca values
			getStatementParents(info.users[0], parents);
			onePastCommonAncestor = parents.begin() + 1; // we know that there is at least one parent so this is safe
		}
		else
		{
			// this happens for SSA values in general
			getStatementParents(*firstAssignment, parents);
			onePastCommonAncestor = parents.end();
			
			for (auto userIter = info.users.begin(); userIter != info.users.end(); ++userIter)
			{
				if (userIter != firstAssignment)
				{
					SmallVector<PrintableScope*, 10> compareParents;
					getStatementParents(*userIter, compareParents);
					auto closestAncestor = mismatch(parents.begin(), onePastCommonAncestor, compareParents.begin(), compareParents.end()).first;
					onePastCommonAncestor = min(onePastCommonAncestor, closestAncestor);
				}
			}
		}
		
		// print declaration/definition
		string newLine;
		raw_string_ostream lineSS(newLine);
		declare(lineSS, tokenKey->getExpressionType(ctx), variable);
		if (onePastCommonAncestor == parents.end() && firstAssignment != info.users.end())
		{
			// modify statement to make it a definition since the first assignment is in the common ancestor
			auto line = cast<PrintableLine>(*firstAssignment);
			lineSS << " = " << (&*line->getLine() + variable.size() + 3);
			line->setLine(lineSS.str().c_str());
		}
		else
		{
			// insert new line in closest parent
			lineSS << ";";
			auto closestAncestor = *(onePastCommonAncestor - 1);
			closestAncestor->prependItem(lineSS.str().c_str());
		}
	}
}

StatementPrintVisitor::StatementPrintVisitor(AstContext& ctx, bool tokenize)
: ctx(ctx), tokenize(tokenize), parentExpression(nullptr), currentExpression(nullptr), os(currentValue)
{
	currentScope = ctx.getPool().allocate<PrintableScope>(ctx.getPool(), nullptr);
}

StatementPrintVisitor::~StatementPrintVisitor()
{
}

void StatementPrintVisitor::visit(const ExpressionUser &user)
{
	const Expression* oldParent = parentExpression;
	if (auto expr = dyn_cast<Expression>(&user))
	{
		assert(os.str().length() == 0);
		if (auto token = getIdentifier(*expr))
		{
			usedByStatement.push_back(expr);
			os << token->token;
			return;
		}
		
		parentExpression = currentExpression;
		currentExpression = expr;
	}
	
	AstVisitor::visit(user);
	assert(!isa<Statement>(user) || os.str().length() == 0);
	
	if (isa<Expression>(user))
	{
		currentExpression = parentExpression;
		parentExpression = oldParent;
	}
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
	bool formatAsHex = false;
	
	// Format as hex if one of these matches:
	// 1- the parent expression is a cast to pointer;
	// 2- the parent expression is is a bitwise operator and the number is greater than 9.
	if (auto nary = dyn_cast_or_null<NAryOperatorExpression>(parentExpression))
	{
		if (numeric.ui64 > 9)
		{
			switch (nary->getType())
			{
				case NAryOperatorExpression::BitwiseAnd:
				case NAryOperatorExpression::BitwiseOr:
				case NAryOperatorExpression::BitwiseXor:
					formatAsHex = true;
					break;
					
				default: break;
			}
		}
	}
	else if (auto cast = dyn_cast_or_null<CastExpression>(parentExpression))
	{
		formatAsHex = isa<PointerExpressionType>(cast->getExpressionType(ctx));
	}
	
	if (formatAsHex)
	{
		(os << "0x").write_hex(numeric.ui64);
	}
	else
	{
		os << numeric.si64;
	}
}

void StatementPrintVisitor::visitToken(const TokenExpression& token)
{
	assert(token.token[0] != '\0');
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
void StatementPrintVisitor::print(AstContext& ctx, raw_ostream &os, const ExpressionUser& user, bool tokenize)
{
	StatementPrintVisitor printer(ctx, tokenize);
	printer.visit(user);
	
	if (isa<Statement>(user))
	{
		if (tokenize)
		{
			printer.insertDeclarations();
		}
		printer.currentScope->print(os, 0);
	}
	else
	{
		os << printer.os.str() << '\n';
	}
}

void StatementPrintVisitor::declare(raw_ostream& os, const ExpressionType &type, const string &variable)
{
	CTypePrinter::declare(os, type, variable);
}

void StatementPrintVisitor::visitIfElse(const IfElseStatement& ifElse)
{
	string prefix;
	raw_string_ostream outSS(prefix);
	
	const StatementList* nextStatementList = nullptr;
	const Statement* nextStatement = &ifElse;
	while (const auto nextIfElse = dyn_cast_or_null<IfElseStatement>(nextStatement))
	{
		auto scope = ctx.getPool().allocate<PrintableScope>(ctx.getPool(), currentScope);
		
		visit(*nextIfElse->getCondition());
		fillUsers(scope);
		outSS << "if (" << take(os) << ')';
		
		scope->setPrefix(take(outSS).c_str());
		
		visit(scope, nextIfElse->getIfBody());
		
		outSS << "else ";
		nextStatementList = &nextIfElse->getElseBody();
		nextStatement = nextStatementList->single();
	}
	
	if (nextStatement != nullptr)
	{
		auto scope = ctx.getPool().allocate<PrintableScope>(ctx.getPool(), currentScope);
		scope->setPrefix(take(outSS).c_str());
		
		visit(scope, *nextStatementList);
	}
}

void StatementPrintVisitor::visitLoop(const LoopStatement& loop)
{
	string prefix;
	raw_string_ostream outSS(prefix);
	auto scope = ctx.getPool().allocate<PrintableScope>(ctx.getPool(), currentScope);
	
	if (loop.getPosition() == LoopStatement::PreTested)
	{
		visit(*loop.getCondition());
		fillUsers(scope);
		outSS << "while (" << take(os) << ')';
		scope->setPrefix(take(outSS).c_str());
		
		visit(scope, loop.getLoopBody());
	}
	else
	{
		assert(loop.getPosition() == LoopStatement::PostTested);
		
		// do...while loops need special treatment to embed the condition calculation inside the loop
		
		pushScope(scope, [&] {
			visitAll(*this, loop.getLoopBody());
			visit(*loop.getCondition());
		});
		
		fillUsers(scope);
		outSS << "while (" << take(os) << ");";
		scope->setPrefix("do");
		scope->setSuffix(take(outSS).c_str());
		currentScope->appendItem(scope);
	}
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
	auto user = currentScope->appendItem(take(outSS).c_str());
	fillUsers(user);
}

void StatementPrintVisitor::visitExpr(const ExpressionStatement& expression)
{
	const Expression& expr = *expression.getExpression();
	visit(expr);
	
	// Only print something if the expression wasn't turned into a token.
	if (tokens.find(&expr) == tokens.end())
	{
		os << ';';
		auto user = currentScope->appendItem(take(os).c_str());
		fillUsers(user);
	}
	else
	{
		os.str().clear();
		usedByStatement.clear();
	}
}
