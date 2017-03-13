//
// statements.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__ast_statements_h
#define fcd__ast_statements_h

#include <iterator>
#include "expression_use.h"
#include "expressions.h"
#include "not_null.h"

class Statement;

class StatementList
{
	Statement* owner;
	Statement* first;
	Statement* last;
	
public:
	class StatementIterator : public std::iterator<std::bidirectional_iterator_tag, Statement*>
	{
		Statement* current;
		
	public:
		StatementIterator(std::nullptr_t)
		: current(nullptr)
		{
		}
		
		StatementIterator(Statement* statement)
		: current(statement)
		{
		}
		
		StatementIterator(const StatementIterator&) = default;
		StatementIterator(StatementIterator&&) = default;
		
		Statement* operator*() { return current; }
		
		bool operator==(const StatementIterator& that) const { return current == that.current; }
		bool operator!=(const StatementIterator& that) const { return !(*this == that); }
		
		StatementIterator& operator++();
		StatementIterator& operator--();
		
		StatementIterator operator++(int)
		{
			StatementIterator copy = *this;
			operator++();
			return copy;
		}
		
		StatementIterator operator--(int)
		{
			StatementIterator copy = *this;
			operator--();
			return copy;
		}
	};
	
	explicit StatementList(Statement* parent)
	: owner(parent)
	{
	}
	
	StatementList(Statement* parent, StatementList&& that)
	: StatementList(parent)
	{
		first = that.first;
		last = that.last;
		that.first = nullptr;
		that.last = nullptr;
	}
	
	StatementList(std::initializer_list<Statement*> statements);
	
	Statement* parent() { return owner; }
	Statement* front() { return first; }
	Statement* back() { return last; }
	
	bool empty() const { return first == nullptr; }
	
	StatementIterator begin() { return StatementIterator(first); }
	StatementIterator end() { return StatementIterator(nullptr); }
	
	static void insert(NOT_NULL(Statement) location, NOT_NULL(Statement) statement);
	void insert(StatementIterator iter, NOT_NULL(Statement) statement);
	
	static void erase(NOT_NULL(Statement) statement);
	StatementIterator erase(StatementIterator iter);
	
	void clear();
};

// Temporary statement list, destroyed at the end of the scope like an ExpressionReference.
class StatementReference
{
	StatementList list;
	
public:
	StatementReference(std::nullptr_t)
	: list(nullptr)
	{
	}
	
	~StatementReference() { list.clear(); }
	
	StatementList* operator->() { return &list; }
	StatementList&& take() && { return std::move(list); }
};

// In opposition to expressions, statements always have a fixed number of use slots. Statements also never create
// expressions. This makes it much less useful to systematically carry around a reference to the AstContext.
class Statement : public ExpressionUser
{
	friend class StatementList;
	StatementList* list;
	Statement* previous;
	Statement* next;
	
public:
	static bool classof(const ExpressionUser* user)
	{
		return user->getUserType() >= StatementMin && user->getUserType() < StatementMax;
	}
	
	Statement(UserType type, unsigned allocatedUses = 0)
	: ExpressionUser(type, allocatedUses)
	{
		assert(type >= StatementMin && type < StatementMax);
	}
	
	Statement* getParent()
	{
		return list == nullptr ? nullptr : list->parent();
	}
};

class ExpressionStatement final : public Statement
{
public:
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == Expr;
	}
	
	ExpressionStatement(NOT_NULL(Expression) expr)
	: Statement(Expr, 1)
	{
		setExpression(expr);
	}
	
	OPERAND_GET_SET(Expression, 0)
	void discardExpression() { getOperandUse(0).setUse(nullptr); }
};

struct KeywordStatement final : public Statement
{
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == Keyword;
	}
	
	NOT_NULL(const char) name;
	
	KeywordStatement(const char* name, Expression* operand = nullptr)
	: Statement(Keyword, 1), name(name)
	{
		if (operand != nullptr)
		{
			setOperand(operand);
		}
	}
	
	// OPERAND_GET_SET assumes operands that are never null, but this one can be.
	Expression* getOperand() { return llvm::cast_or_null<Expression>(ExpressionUser::getOperand(0)); }
	const Expression* getOperand() const { return llvm::cast_or_null<Expression>(ExpressionUser::getOperand(0)); }
	void setOperand(Expression* op) { ExpressionUser::getOperandUse(0).setUse(op); }
	void discardExpression() { setOperand(nullptr); }
};

// "Non-terminal" statements (can contain more statements)
class IfElseStatement final : public Statement
{
	StatementList ifBody;
	StatementList elseBody;
	
protected:
	virtual void dropAllStatementReferences() override;
	
public:
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == IfElse;
	}
	
	IfElseStatement(NOT_NULL(Expression) condition)
	: Statement(IfElse, 1), ifBody(this), elseBody(this)
	{
		setCondition(condition);
	}
	
	IfElseStatement(NOT_NULL(Expression) condition, StatementList&& ifBody)
	: Statement(IfElse, 1), ifBody(this, std::move(ifBody)), elseBody(this)
	{
		setCondition(condition);
	}
	
	IfElseStatement(NOT_NULL(Expression) condition, StatementList&& ifBody, StatementList&& elseBody)
	: Statement(IfElse, 1), ifBody(this, std::move(ifBody)), elseBody(this, std::move(elseBody))
	{
		setCondition(condition);
	}
	
	StatementList& getIfBody() { return ifBody; }
	const StatementList& getIfBody() const { return ifBody; }
	StatementList& getElseBody() { return elseBody; }
	const StatementList& getElseBody() const { return elseBody; }
	
	OPERAND_GET_SET(Condition, 0)
};

class LoopStatement final : public Statement
{
public:
	enum ConditionPosition
	{
		PreTested, // while
		PostTested, // do ... while
	};
	
private:
	ConditionPosition position;
	StatementList loopBody;
	
protected:
	virtual void dropAllStatementReferences() override;
	
public:
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == Loop;
	}
	
	LoopStatement(NOT_NULL(Expression) condition, ConditionPosition position)
	: Statement(Loop, 1), position(position), loopBody(this)
	{
		setCondition(condition);
	}
	
	LoopStatement(NOT_NULL(Expression) condition, ConditionPosition position, StatementList&& loopBody)
	: Statement(Loop, 1), position(position), loopBody(this, std::move(loopBody))
	{
		setCondition(condition);
	}
	
	ConditionPosition getPosition() const { return position; }
	void setPosition(ConditionPosition condPos) { position = condPos; }
	
	StatementList& getLoopBody() { return loopBody; }
	const StatementList& getLoopBody() const { return loopBody; }
	
	OPERAND_GET_SET(Condition, 0)
	void discardCondition() { getOperandUse(0).setUse(nullptr); }
};

#endif /* fcd__ast_statements_h */
