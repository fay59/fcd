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
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <string>

class ExpressionPrintVisitor : public ExpressionVisitor
{
	llvm::raw_ostream& os;

	void printWithParentheses(unsigned precedence, Expression* expression);
	
public:
	inline ExpressionPrintVisitor(llvm::raw_ostream& os)
	: os(os)
	{
	}
	
	virtual void visitUnary(UnaryOperatorExpression* unary) override;
	virtual void visitNAry(NAryOperatorExpression* nary) override;
	virtual void visitTernary(TernaryExpression* ternary) override;
	virtual void visitNumeric(NumericExpression* numeric) override;
	virtual void visitToken(TokenExpression* token) override;
	virtual void visitCall(CallExpression* call) override;
	virtual void visitCast(CastExpression* cast) override;
	virtual void visitAggregate(AggregateExpression* agg) override;
	virtual void visitSubscript(SubscriptExpression* subscript) override;
	virtual void visitAssembly(AssemblyExpression* assembly) override;
	
	virtual ~ExpressionPrintVisitor() = default;
};

class StatementPrintVisitor : public StatementVisitor
{
	ExpressionPrintVisitor expressionPrinter;
	
	unsigned indentCount;
	llvm::raw_ostream& os;
	
	std::string indent() const;
	void printWithIndent(Statement* statement);
	void visitIfElse(IfElseStatement* ifElse, const std::string& firstLineIndent);
	
public:
	inline StatementPrintVisitor(llvm::raw_ostream& os, unsigned indentCount = 0)
	: expressionPrinter(os), indentCount(indentCount), os(os)
	{
	}
	
	virtual void visitSequence(SequenceStatement* sequence) override;
	virtual void visitIfElse(IfElseStatement* ifElse) override;
	virtual void visitLoop(LoopStatement* loop) override;
	virtual void visitKeyword(KeywordStatement* keyword) override;
	virtual void visitExpression(ExpressionStatement* expression) override;
	virtual void visitDeclaration(DeclarationStatement* declaration) override;
	virtual void visitAssignment(AssignmentStatement* assignment) override;
	
	virtual ~StatementPrintVisitor() = default;
};

class StatementShortPrintVisitor : public StatementVisitor
{
	ExpressionPrintVisitor expressionPrinter;
	llvm::raw_ostream& os;
	
public:
	inline StatementShortPrintVisitor(llvm::raw_ostream& os)
	: expressionPrinter(os), os(os)
	{
	}
	
	virtual void visitSequence(SequenceStatement* sequence) override;
	virtual void visitIfElse(IfElseStatement* ifElse) override;
	virtual void visitLoop(LoopStatement* loop) override;
	virtual void visitKeyword(KeywordStatement* keyword) override;
	virtual void visitExpression(ExpressionStatement* expression) override;
	virtual void visitDeclaration(DeclarationStatement* declaration) override;
	virtual void visitAssignment(AssignmentStatement* assignment) override;
	
	virtual ~StatementShortPrintVisitor() = default;
};

#endif /* fcd__ast_print_h */
