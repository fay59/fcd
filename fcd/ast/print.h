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
#include "print_item.h"
#include "visitor.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <list>
#include <string>
#include <unordered_map>
#include <unordered_set>

class StatementPrintVisitor final : public AstVisitor<StatementPrintVisitor>
{
	struct Tokenization
	{
		std::string token;
		//llvm::SmallVector<PrintableStatement*, 10> users;
		std::vector<PrintableStatement*> users;
	};
	
	AstContext& ctx;
	std::unordered_map<const Expression*, Tokenization> tokens;
	std::unordered_set<const Expression*> noTokens;
	bool tokenize;
	
	std::string currentValue;
	PrintableScope* currentScope;
	llvm::raw_string_ostream os;
	llvm::SmallVector<const Expression*, 16> usedByStatement;
	
	Tokenization* getIdentifier(const Expression& expression);
	
	void printWithParentheses(unsigned precedence, const Expression& expression);
	void visit(PrintableScope* childScope, const Statement& stmt);
	void fillUsers(PrintableStatement* user);
	void insertDeclarations();
	
	StatementPrintVisitor(AstContext& ctx, bool tokenize);
	~StatementPrintVisitor();
	
public:
	static void print(AstContext& ctx, llvm::raw_ostream& os, const ExpressionUser& statement, bool tokenize = true);
	static void declare(llvm::raw_ostream& os, const ExpressionType& type, const std::string& variable);
	
	void visit(const ExpressionUser& user);
	
	void visitUnaryOperator(const UnaryOperatorExpression& unary);
	void visitNAryOperator(const NAryOperatorExpression& nary);
	void visitMemberAccess(const MemberAccessExpression& assignable);
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
