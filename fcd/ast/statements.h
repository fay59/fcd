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

#include "expression_use.h"
#include "expressions.h"
#include "llvm_warnings.h"
#include "not_null.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

class StatementVisitor;

// In opposition to expressions, statements always have a fixed number of use slots. Statements also never create
// expressions. This makes it much less useful to systematically carry around a reference to the AstContext.
class Statement : public ExpressionUser
{
public:
	Statement(UserType type, unsigned allocatedUses = 0)
	: ExpressionUser(type, allocatedUses)
	{
		assert(type >= StatementMin && type < StatementMax);
	}
	
	void printShort(llvm::raw_ostream& os) const;
	void print(llvm::raw_ostream& os) const;
	void dump() const;
};

struct ExpressionStatement : public Statement
{
	static bool classof(const Statement* node)
	{
		return node->getUserType() == Expr;
	}
	
	ExpressionStatement(NOT_NULL(Expression) expr)
	: Statement(Expr, 1)
	{
		setExpression(expr);
	}
	
	OPERAND_GET_SET(Expression, 0)
};

struct SequenceStatement : public Statement
{
	PooledDeque<NOT_NULL(Statement)> statements;
	
	static bool classof(const Statement* node)
	{
		return node->getUserType() == Sequence;
	}
	
	SequenceStatement(DumbAllocator& pool)
	: Statement(Sequence), statements(pool)
	{
	}
};

struct IfElseStatement : public Statement
{
	NOT_NULL(Statement) ifBody;
	Statement* elseBody;
	
	static bool classof(const Statement* node)
	{
		return node->getUserType() == IfElse;
	}
	
	IfElseStatement(NOT_NULL(Expression) condition, NOT_NULL(Statement) ifBody, Statement* elseBody = nullptr)
	: Statement(IfElse, 1), ifBody(ifBody), elseBody(elseBody)
	{
		setCondition(condition);
	}
	
	OPERAND_GET_SET(Condition, 0)
};

struct LoopStatement : public Statement
{
	enum ConditionPosition
	{
		PreTested, // while
		PostTested, // do ... while
	};
	
	ConditionPosition position;
	NOT_NULL(Statement) loopBody;
	
	static bool classof(const Statement* node)
	{
		return node->getUserType() == Loop;
	}
	
	LoopStatement(NOT_NULL(Expression) condition, ConditionPosition position, NOT_NULL(Statement) body)
	: Statement(Loop, 1), position(position), loopBody(body)
	{
		setCondition(condition);
	}
	
	OPERAND_GET_SET(Condition, 0)
};

struct KeywordStatement : public Statement
{
	static bool classof(const Statement* node)
	{
		return node->getUserType() == Keyword;
	}
	
	static KeywordStatement* breakNode;
	
	NOT_NULL(const char) name;
	
	KeywordStatement(const char* name, Expression* operand = nullptr)
	: Statement(Keyword, 1), name(name)
	{
		if (operand != nullptr)
		{
			setOperand(operand);
		}
	}
	
	using ExpressionUser::getOperand;
	using ExpressionUser::setOperand;
	OPERAND_GET_SET(Operand, 0)
};

#endif /* fcd__ast_statements_h */
