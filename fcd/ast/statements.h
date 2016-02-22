//
// statements.h
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

#ifndef fcd__ast_statements_h
#define fcd__ast_statements_h

#include "dumb_allocator.h"
#include "expressions.h"
#include "llvm_warnings.h"
#include "not_null.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

class StatementVisitor;

struct Statement
{
	enum StatementType
	{
		Sequence, IfElse, Loop, Expr, Keyword, Declaration, Assignment
	};
	
	void printShort(llvm::raw_ostream& os) const;
	void print(llvm::raw_ostream& os) const;
	void dump() const;
	
	virtual StatementType getType() const = 0;
	virtual void visit(StatementVisitor& visitor) = 0;
};

struct ExpressionStatement final : public Statement
{
	NOT_NULL(Expression) expression;
	
	static inline bool classof(const Statement* node)
	{
		return node->getType() == Expr;
	}
	
	inline ExpressionStatement(Expression* expr)
	: expression(expr)
	{
	}
	
	virtual inline StatementType getType() const override { return Expr; }
	virtual void visit(StatementVisitor& visitor) override;
};

struct SequenceStatement final : public Statement
{
	PooledDeque<NOT_NULL(Statement)> statements;
	
	static inline bool classof(const Statement* node)
	{
		return node->getType() == Sequence;
	}
	
	inline SequenceStatement(DumbAllocator& pool)
	: statements(pool)
	{
	}
	
	virtual inline StatementType getType() const override { return Sequence; }
	virtual void visit(StatementVisitor& visitor) override;
};

struct IfElseStatement final : public Statement
{
	ExpressionStatement conditionExpression;
	NOT_NULL(Expression)& condition;
	NOT_NULL(Statement) ifBody;
	Statement* elseBody;
	
	static inline bool classof(const Statement* node)
	{
		return node->getType() == IfElse;
	}
	
	inline IfElseStatement(Expression* condition, Statement* ifBody, Statement* elseBody = nullptr)
	: conditionExpression(condition), condition(conditionExpression.expression), ifBody(ifBody), elseBody(elseBody)
	{
	}
	
	virtual inline StatementType getType() const override { return IfElse; }
	virtual void visit(StatementVisitor& visitor) override;
};

struct LoopStatement final : public Statement
{
	enum ConditionPosition {
		PreTested, // while
		PostTested, // do ... while
	};
	
	ExpressionStatement conditionExpression;
	NOT_NULL(Expression)& condition;
	ConditionPosition position;
	NOT_NULL(Statement) loopBody;
	
	static inline bool classof(const Statement* node)
	{
		return node->getType() == Loop;
	}
	
	LoopStatement(Statement* body); // creates a `while (true)`
	
	inline LoopStatement(Expression* condition, ConditionPosition position, Statement* body)
	: conditionExpression(condition), condition(conditionExpression.expression), position(position), loopBody(body)
	{
	}
	
	inline bool isEndless() const;
	
	virtual inline StatementType getType() const override { return Loop; }
	virtual void visit(StatementVisitor& visitor) override;
};

struct KeywordStatement final : public Statement
{
	static inline bool classof(const Statement* node)
	{
		return node->getType() == Keyword;
	}
	
	static KeywordStatement* breakNode;
	
	NOT_NULL(const char) name;
	Expression* operand;
	
	inline KeywordStatement(const char* name, Expression* operand = nullptr)
	: name(name), operand(operand)
	{
	}
	
	virtual inline StatementType getType() const override { return Keyword; }
	virtual void visit(StatementVisitor& visitor) override;
};

struct DeclarationStatement final : public Statement
{
	NOT_NULL(TokenExpression) type;
	NOT_NULL(TokenExpression) name;
	const char* comment;
	size_t orderHint; // This field helps order declarations when they must be printed.
	
	static inline bool classof(const Statement* node)
	{
		return node->getType() == Declaration;
	}
	
	inline DeclarationStatement(TokenExpression* type, TokenExpression* name, const char* comment = nullptr)
	: type(type), name(name), comment(comment), orderHint(0)
	{
	}
	
	virtual inline StatementType getType() const override { return Declaration; }
	virtual void visit(StatementVisitor& visitor) override;
};

struct AssignmentStatement final : public Statement
{
	NOT_NULL(Expression) left;
	NOT_NULL(Expression) right;
	bool isSsa;
	
	static inline bool classof(const Statement* node)
	{
		return node->getType() == Assignment;
	}
	
	inline AssignmentStatement(Expression* left, Expression* right, bool ssa = true)
	: left(left), right(right), isSsa(ssa)
	{
	}
	
	virtual inline StatementType getType() const override { return Assignment; }
	virtual void visit(StatementVisitor& visitor) override;
};

bool LoopStatement::isEndless() const
{
	return condition == TokenExpression::trueExpression;
}

#endif /* fcd__ast_statements_h */
