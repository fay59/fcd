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
	
	class CTypePrinter
	{
		static void printMiddleIfAny(raw_ostream& os, const string& middle)
		{
			if (middle.size() > 0)
			{
				if (isalpha(middle[0]))
				{
					os << ' ';
				}
				os << middle;
			}
		}
		
		static void print(raw_ostream& os, const VoidExpressionType&, string middle)
		{
			os << "void";
			printMiddleIfAny(os, middle);
		}
		
		static void print(raw_ostream& os, const IntegerExpressionType& intTy, string middle)
		{
			if (intTy.getBits() == 1)
			{
				os << "bool";
			}
			else
			{
				os << (intTy.isSigned() ? "" : "u") << "int" << intTy.getBits() << "_t";
			}
			printMiddleIfAny(os, middle);
		}
		
		static void print(raw_ostream& os, const PointerExpressionType& pointerTy, string middle)
		{
			string tempMiddle;
			raw_string_ostream midOs(tempMiddle);
			const auto& nestedType = pointerTy.getNestedType();
			bool wrapWithParentheses = isa<ArrayExpressionType>(nestedType) || isa<FunctionExpressionType>(nestedType);
			
			if (wrapWithParentheses) midOs << '(';
			midOs << '*';
			printMiddleIfAny(midOs, middle);
			if (wrapWithParentheses) midOs << ')';
			
			print(os, nestedType, move(midOs.str()));
		}
		
		static void print(raw_ostream& os, const ArrayExpressionType& arrayTy, string middle)
		{
			raw_string_ostream(middle) << '[' << arrayTy.size() << ']';
			print(os, arrayTy.getNestedType(), move(middle));
		}
		
		static void print(raw_ostream& os, const StructExpressionType& structTy, string middle)
		{
			os << "struct {";
			if (structTy.size() > 0)
			{
				os << ' ';
				for (auto iter = structTy.begin(); iter != structTy.end(); ++iter)
				{
					print(os, iter->type, iter->name);
					os << "; ";
				}
			}
			os << "} " << move(middle);
		}
		
		static void print(raw_ostream& os, const FunctionExpressionType& funcTy, string middle)
		{
			string result;
			raw_string_ostream rs(result);
			rs << middle << '(';
			
			auto iter = funcTy.begin();
			if (iter != funcTy.end())
			{
				print(rs, iter->type, iter->name);
				for (++iter; iter != funcTy.end(); ++iter)
				{
					rs << ", ";
					print(rs, iter->type, iter->name);
				}
			}
			
			rs << ')';
			print(os, funcTy.getReturnType(), move(rs.str()));
		}
		
	public:
		static void declare(raw_ostream& os, const ExpressionType& type, const string& identifier)
		{
			print(os, type, identifier);
		}
		
		static void print(raw_ostream& os, const ExpressionType& type, string middle = "")
		{
			switch (type.getType())
			{
				case ExpressionType::Void:
					return print(os, cast<VoidExpressionType>(type), move(middle));
				case ExpressionType::Integer:
					return print(os, cast<IntegerExpressionType>(type), move(middle));
				case ExpressionType::Pointer:
					return print(os, cast<PointerExpressionType>(type), move(middle));
				case ExpressionType::Array:
					return print(os, cast<ArrayExpressionType>(type), move(middle));
				case ExpressionType::Structure:
					return print(os, cast<StructExpressionType>(type), move(middle));
				case ExpressionType::Function:
					return print(os, cast<FunctionExpressionType>(type), move(middle));
				default:
					llvm_unreachable("unhandled expression type");
			}
		}
	};
	
	template<typename T>
	struct ScopedPush
	{
		list<T>* collection;
		
		template<typename... Args>
		ScopedPush(list<T>& collection, Args&&... args)
		: collection(&collection)
		{
			this->collection->emplace_back(forward<Args>(args)...);
		}
		
		ScopedPush(ScopedPush&& that)
		: collection(that.collection)
		{
			that.collection = nullptr;
		}
		
		~ScopedPush()
		{
			if (collection != nullptr)
			{
				collection->pop_back();
			}
		}
	};
	
	template<typename T, typename... Args>
	ScopedPush<T> scopePush(list<T>& collection, Args&&... args)
	{
		return ScopedPush<T>(collection, forward<Args>(args)...);
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
	
	bool shouldReduceIntoToken(const Expression& expression)
	{
		if (isa<AssignableExpression>(expression))
		{
			return true;
		}
		else if (isa<UnaryOperatorExpression>(expression))
		{
			return false;
		}
		else if (auto memberAcces = dyn_cast<MemberAccessExpression>(&expression))
		{
			return shouldReduceIntoToken(*memberAcces->getBaseExpression());
		}
		
		if (!expression.uses_many())
		{
			return false;
		}
		
		return true;
	}
	
	constexpr char nl = '\n';
}

struct StatementPrintVisitor::PrintInfo
{
	llvm::raw_ostream* targetScope;
	const ExpressionUser* user;
	std::string buffer;
	llvm::raw_string_ostream thisScope;
	unsigned indentCount;
	
	PrintInfo(const ExpressionUser* user, llvm::raw_ostream& os, unsigned indent)
	: targetScope(&os), user(user), thisScope(buffer), indentCount(indent)
	{
	}
	
	~PrintInfo()
	{
		*targetScope << thisScope.str();
	}
	
	std::string indent() const;
};

raw_string_ostream& StatementPrintVisitor::os()
{
	 return printInfo.back().thisScope;
}

string StatementPrintVisitor::PrintInfo::indent() const
{
	return string(indentCount, '\t');
}

unsigned StatementPrintVisitor::indentCount() const
{
	return printInfo.back().indentCount;
}

const string* StatementPrintVisitor::hasIdentifier(const Expression &expression)
{
	auto iter = tokens.find(&expression);
	return iter == tokens.end() ? nullptr : &iter->second;
}

bool StatementPrintVisitor::identifyIfNecessary(const Expression &expression)
{
	if (!tokenize || noTokens.count(&expression) != 0)
	{
		return false;
	}
	
	if (!shouldReduceIntoToken(expression))
	{
		noTokens.insert(&expression);
		return false;
	}
	
	string& value = printInfo.back().thisScope.str();
	string& identifier = tokens[&expression];
	assert(identifier.empty());
	
	if (auto assignable = dyn_cast<AssignableExpression>(&expression))
	{
		raw_string_ostream(identifier) << assignable->prefix << tokens.size();
	}
	else
	{
		raw_string_ostream(identifier) << "anon" << tokens.size();
	}
	
	// Find best place to declare variable
	auto commonAncestor = expression.ancestorOfAllUses();
	assert(commonAncestor != nullptr);
	
	if (isa<IfElseStatement>(commonAncestor))
	{
		// You can't put a declaration in an if-else statement that would reach its two branches.
		commonAncestor = commonAncestor->getParent();
	}
	
	auto firstStatement = find_if(printInfo.rbegin(), printInfo.rend(), [&](PrintInfo& info)
	{
		return info.user != nullptr && isa<Statement>(info.user);
	});
	
	auto commonAncestorIter = find_if(firstStatement, printInfo.rend(), [&](PrintInfo& info)
	{
		return info.user == commonAncestor;
	});
	
	auto& decl = *commonAncestorIter->targetScope;
	decl << commonAncestorIter->indent();
	CTypePrinter::declare(decl, expression.getExpressionType(ctx), identifier);
	if (value.empty())
	{
		decl << ";\n";
	}
	else
	{
		decl << " = " << value << ";\n";
	}
	value = identifier;
	return true;
}

void StatementPrintVisitor::printWithParentheses(unsigned int precedence, const Expression& expression)
{
	auto pushed = scopePush(printInfo, nullptr, os(), indentCount());
	visit(expression);
	
	if (needsParentheses(precedence, expression) && tokens.find(&expression) == tokens.end())
	{
		string expression = printInfo.back().thisScope.str();
		printInfo.back().buffer.clear();
		os() << '(' << expression << ')';
	}
}

StatementPrintVisitor::StatementPrintVisitor(AstContext& ctx, llvm::raw_ostream& os, unsigned initialIndent, bool tokenize)
: ctx(ctx), tokenize(tokenize)
{
	printInfo.emplace_back(nullptr, os, initialIndent);
}

StatementPrintVisitor::~StatementPrintVisitor()
{
}

#pragma mark - Expressions
void StatementPrintVisitor::visitUnaryOperator(const UnaryOperatorExpression& unary)
{
	if (auto id = hasIdentifier(unary))
	{
		os() << *id;
		return;
	}
	auto pushed = scopePush(printInfo, &unary, os(), indentCount());
	
	unsigned precedence = numeric_limits<unsigned>::max();
	auto type = unary.getType();
	if (type > UnaryOperatorExpression::Min && type < UnaryOperatorExpression::Max)
	{
		os() << operatorName[type];
		precedence = operatorPrecedence[type];
	}
	else
	{
		os() << badOperator;
	}
	printWithParentheses(precedence, *unary.getOperand());
	identifyIfNecessary(unary);
}

void StatementPrintVisitor::visitNAryOperator(const NAryOperatorExpression& nary)
{
	assert(nary.operands_size() > 0);
	if (auto id = hasIdentifier(nary))
	{
		os() << *id;
		return;
	}
	auto pushed = scopePush(printInfo, &nary, os(), indentCount());
	
	const string* displayName = &badOperator;
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
	
	for (; iter != nary.operands_end(); ++iter)
	{
		os() << ' ' << *displayName << ' ';
		printWithParentheses(precedence, *iter->getUse());
	}
	identifyIfNecessary(nary);
}

void StatementPrintVisitor::visitMemberAccess(const MemberAccessExpression &assignable)
{
	// member accesses are never reduced into tokens, but call it anyway for uniformity.
	if (auto id = hasIdentifier(assignable))
	{
		assert(false);
		os() << *id;
		return;
	}
	
	auto pushed = scopePush(printInfo, &assignable, os(), indentCount());
	printWithParentheses(operatorPrecedence[assignable.getAccessType()], *assignable.getBaseExpression());
	os() << operatorName[assignable.getAccessType()] << assignable.getFieldName();
}

void StatementPrintVisitor::visitTernary(const TernaryExpression& ternary)
{
	if (auto id = hasIdentifier(ternary))
	{
		os() << *id;
		return;
	}
	auto pushed = scopePush(printInfo, &ternary, os(), indentCount());
	
	printWithParentheses(ternaryPrecedence, *ternary.getCondition());
	os() << " ? ";
	printWithParentheses(ternaryPrecedence, *ternary.getTrueValue());
	os() << " : ";
	printWithParentheses(ternaryPrecedence, *ternary.getFalseValue());
	identifyIfNecessary(ternary);
}

void StatementPrintVisitor::visitNumeric(const NumericExpression& numeric)
{
	os() << numeric.si64;
}

void StatementPrintVisitor::visitToken(const TokenExpression& token)
{
	os() << token.token;
}

void StatementPrintVisitor::visitCall(const CallExpression& call)
{
	if (auto id = hasIdentifier(call))
	{
		os() << *id;
		return;
	}
	auto pushed = scopePush(printInfo, &call, os(), indentCount());
	
	auto callTarget = call.getCallee();
	printWithParentheses(callPrecedence, *callTarget);
	
	const auto& funcPointerType = cast<PointerExpressionType>(callTarget->getExpressionType(ctx));
	const auto& funcType = cast<FunctionExpressionType>(funcPointerType.getNestedType());
	size_t paramIndex = 0;
	os() << '(';
	auto iter = call.params_begin();
	auto end = call.params_end();
	if (iter != end)
	{
		const string& paramName = funcType[paramIndex].name;
		if (paramName != "")
		{
			os() << paramName << '=';
			paramIndex++;
		}
		
		visit(*iter->getUse());
		for (++iter; iter != end; ++iter)
		{
			os() << ", ";
			const string& paramName = funcType[paramIndex].name;
			if (paramName != "")
			{
				os() << paramName << '=';
				paramIndex++;
			}
			visit(*iter->getUse());
		}
	}
	os() << ')';
	identifyIfNecessary(call);
}

void StatementPrintVisitor::visitCast(const CastExpression& cast)
{
	if (auto id = hasIdentifier(cast))
	{
		os() << *id;
		return;
	}
	auto pushed = scopePush(printInfo, &cast, os(), indentCount());
	
	os() << '(';
	
	// XXX: are __sext and __zext annotations relevant? they only mirror whether
	// there's a "u" or not in front of the integer type.
	if (auto intType = dyn_cast<IntegerExpressionType>(&cast.getExpressionType(ctx)))
	if (auto innerType = dyn_cast<IntegerExpressionType>(&cast.getCastValue()->getExpressionType(ctx)))
	if (innerType->getBits() < intType->getBits())
	{
		os() << (intType->isSigned() ? "__sext " : "__zext ");
	}
	
	CTypePrinter::print(os(), cast.getExpressionType(ctx));
	os() << ')';
	printWithParentheses(castPrecedence, *cast.getCastValue());
	identifyIfNecessary(cast);
}

void StatementPrintVisitor::visitAggregate(const AggregateExpression& aggregate)
{
	if (auto id = hasIdentifier(aggregate))
	{
		os() << *id;
		return;
	}
	auto pushed = scopePush(printInfo, &aggregate, os(), indentCount());
	
	os() << '{';
	size_t count = aggregate.operands_size();
	if (count > 0)
	{
		auto iter = aggregate.operands_begin();
		visit(*iter->getUse());
		for (++iter; iter != aggregate.operands_end(); ++iter)
		{
			os() << ", ";
			visit(*iter->getUse());
		}
	}
	os() << '}';
	identifyIfNecessary(aggregate);
}

void StatementPrintVisitor::visitSubscript(const SubscriptExpression& subscript)
{
	if (auto id = hasIdentifier(subscript))
	{
		os() << *id;
		return;
	}
	auto pushed = scopePush(printInfo, &subscript, os(), indentCount());
	
	printWithParentheses(subscriptPrecedence, *subscript.getPointer());
	os() << '[';
	visit(*subscript.getIndex());
	os() << ']';
	identifyIfNecessary(subscript);
}

void StatementPrintVisitor::visitAssembly(const AssemblyExpression& assembly)
{
	os() << "(__asm \"" << assembly.assembly << "\")";
}

void StatementPrintVisitor::visitAssignable(const AssignableExpression &assignable)
{
	if (auto id = hasIdentifier(assignable))
	{
		os() << *id;
		return;
	}
	
	auto pushed = scopePush(printInfo, &assignable, os(), indentCount());
	if (tokenize)
	{
		identifyIfNecessary(assignable);
	}
	else
	{
		os() << "«" << assignable.prefix << ":" << &assignable << "»";
	}
}

#pragma mark - Statements
string StatementPrintVisitor::indent() const
{
	return printInfo.back().indent();
}

void StatementPrintVisitor::print(AstContext& ctx, llvm::raw_ostream &os, const ExpressionUser& user, unsigned initialIndent, bool tokenize)
{
	StatementPrintVisitor printer(ctx, os, initialIndent, tokenize);
	printer.visit(user);
}

void StatementPrintVisitor::declare(raw_ostream& os, const ExpressionType &type, const string &variable)
{
	CTypePrinter::declare(os, type, variable);
}

void StatementPrintVisitor::visitIfElse(const IfElseStatement& ifElse, const string &firstLineIndent)
{
	auto pushed = scopePush(printInfo, &ifElse, os(), indentCount());
	
	os() << firstLineIndent << "if (";
	visit(*ifElse.getCondition());
	os() << ")\n";
	
	os() << indent() << "{\n";
	{
		auto pushed = scopePush(printInfo, &ifElse, os(), indentCount() + 1);
		visit(*ifElse.getIfBody());
	}
	os() << indent() << "}\n";
	
	if (auto elseBody = ifElse.getElseBody())
	{
		os() << indent() << "else";
		if (auto otherCase = dyn_cast<IfElseStatement>(elseBody))
		{
			visitIfElse(*otherCase, " ");
		}
		else
		{
			os() << nl << indent() << "{\n";
			{
				auto pushed = scopePush(printInfo, &ifElse, os(), indentCount() + 1);
				visit(*elseBody);
			}
			os() << indent() << "}\n";
		}
	}
}

void StatementPrintVisitor::visitNoop(const NoopStatement &noop)
{
}

void StatementPrintVisitor::visitSequence(const SequenceStatement& sequence)
{
	auto pushed = scopePush(printInfo, &sequence, os(), indentCount());
	for (Statement* child : sequence)
	{
		visit(*child);
	}
}

void StatementPrintVisitor::visitIfElse(const IfElseStatement& ifElse)
{
	visitIfElse(ifElse, indent());
}

void StatementPrintVisitor::visitLoop(const LoopStatement& loop)
{
	auto pushed = scopePush(printInfo, &loop, os(), indentCount());
	
	if (loop.getPosition() == LoopStatement::PreTested)
	{
		os() << indent() << "while (";
		visit(*loop.getCondition());
		os() << ")\n";
		
		os() << indent() << "{\n";
		{
			auto pushed = scopePush(printInfo, &loop, os(), indentCount() + 1);
			visit(*loop.getLoopBody());
		}
		os() << indent() << "}\n";
	}
	else
	{
		assert(loop.getPosition() == LoopStatement::PostTested);
		
		os() << indent() << "do" << nl;
		os() << indent() << "{\n";
		{
			auto pushed = scopePush(printInfo, &loop, os(), indentCount() + 1);
			visit(*loop.getLoopBody());
		}
		os() << indent() << "} while (";
		visit(*loop.getCondition());
		os() << ");\n";
	}
}

void StatementPrintVisitor::visitKeyword(const KeywordStatement& keyword)
{
	auto pushed = scopePush(printInfo, &keyword, os(), indentCount());
	
	os() << indent() << keyword.name;
	if (auto operand = keyword.getOperand())
	{
		os() << ' ';
		visit(*operand);
	}
	os() << ";\n";
}

void StatementPrintVisitor::visitExpr(const ExpressionStatement& expression)
{
	const Expression& expr = *expression.getExpression();
	auto pushed = scopePush(printInfo, &expression, os(), indentCount());
	
	os() << indent();
	visit(expr);
	os() << ";\n";
	
	// Don't print anything if the expression is replaced with a single token.
	if (tokens.find(&expr) != tokens.end())
	{
		os().str().clear();
	}
}
