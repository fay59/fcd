//
// print.h
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

#ifndef fcd__ast_print_h
#define fcd__ast_print_h

#include "llvm_warnings.h"
#include "visitor.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <deque>
#include <string>
#include <unordered_map>

class StatementPrintVisitor : public AstVisitor<StatementPrintVisitor>
{
	struct PrintInfo
	{
		llvm::raw_ostream& targetScope;
		const Statement* statement;
		std::string buffer;
		llvm::raw_string_ostream thisScope;
		
		PrintInfo(const Statement* statement, llvm::raw_ostream& os)
		: targetScope(os), statement(statement), thisScope(buffer)
		{
		}
		
		~PrintInfo()
		{
			thisScope.flush();
			targetScope << buffer;
		}
	};
	
	std::deque<PrintInfo> printInfo;
	std::unordered_map<const Expression*, std::string> tokens;
	
	unsigned indentCount;
	
	llvm::raw_ostream& os() { return printInfo.back().thisScope; }
	std::string indent() const;
	void printWithIndent(const Statement& statement);
	void visitIfElse(const IfElseStatement& ifElse, const std::string& firstLineIndent);
	
	void printWithParentheses(unsigned precedence, const Expression& expression);
	
	inline StatementPrintVisitor(llvm::raw_ostream& os, unsigned initialIndent = 1)
	: indentCount(initialIndent)
	{
		printInfo.emplace_back(nullptr, os);
	}
	
public:
	static void print(llvm::raw_ostream& os, const ExpressionUser& statement);
	
	void visitUnaryOperator(const UnaryOperatorExpression& unary);
	void visitNAryOperator(const NAryOperatorExpression& nary);
	void visitTernary(const TernaryExpression& ternary);
	void visitNumeric(const NumericExpression& numeric);
	void visitToken(const TokenExpression& token);
	void visitCall(const CallExpression& call);
	void visitCast(const CastExpression& cast);
	void visitAggregate(const AggregateExpression& agg);
	void visitSubscript(const SubscriptExpression& subscript);
	void visitAssembly(const AssemblyExpression& assembly);
	void visitAssignable(const AssignableExpression& assignable);
	
	void visitNoop(const NoopStatement& noop);
	void visitSequence(const SequenceStatement& sequence);
	void visitIfElse(const IfElseStatement& ifElse);
	void visitLoop(const LoopStatement& loop);
	void visitKeyword(const KeywordStatement& keyword);
	void visitExpr(const ExpressionStatement& expression);
	
	void visitDefault(const ExpressionUser& user) { llvm_unreachable("missing print code"); }
};

#endif /* fcd__ast_print_h */
