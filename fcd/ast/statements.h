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

#include "expression_use.h"
#include "expressions.h"
#include "not_null.h"

// In opposition to expressions, statements always have a fixed number of use slots. Statements also never create
// expressions. This makes it much less useful to systematically carry around a reference to the AstContext.
class Statement : public ExpressionUser
{
	Statement* parentStatement;
	
protected:
	void takeChild(Statement* child)
	{
		assert(child->parentStatement == nullptr);
		child->parentStatement = this;
	}
	
	void disown(Statement* child)
	{
		assert(child->parentStatement == this);
		child->parentStatement = nullptr;
		llvm::errs() << "disown(" << child << ")\n";
	}
	
public:
	static bool classof(const ExpressionUser* user)
	{
		return user->getUserType() >= StatementMin && user->getUserType() < StatementMax;
	}
	
	Statement(UserType type, unsigned allocatedUses = 0)
	: ExpressionUser(type, allocatedUses), parentStatement(nullptr)
	{
		assert(type >= StatementMin && type < StatementMax);
	}
	
	virtual void replaceChild(NOT_NULL(Statement) child, NOT_NULL(Statement) newChild) = 0;
	
	Statement* getParent() { return parentStatement; }
	const Statement* getParent() const { return parentStatement; }
};

class NoopStatement final : public Statement
{
public:
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == Noop;
	}
	
	NoopStatement()
	: Statement(Noop)
	{
	}
	
	virtual void replaceChild(NOT_NULL(Statement) child, NOT_NULL(Statement) newChild) override;
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
	
	virtual void replaceChild(NOT_NULL(Statement) child, NOT_NULL(Statement) newChild) override;
	
	OPERAND_GET_SET(Expression, 0)
	void discardExpression() { getOperandUse(0).setUse(nullptr); }
};

class SequenceStatement final : public Statement
{
	PooledDeque<NOT_NULL(Statement)> statements;
	
protected:
	virtual void dropAllStatementReferences() override;
	
public:
	typedef PooledDeque<NOT_NULL(Statement)>::iterator iterator;
	typedef PooledDeque<NOT_NULL(Statement)>::const_iterator const_iterator;
	
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == Sequence;
	}
	
	SequenceStatement(DumbAllocator& pool)
	: Statement(Sequence), statements(pool)
	{
	}
	
	iterator begin() { return statements.begin(); }
	const_iterator begin() const { return statements.begin(); }
	const_iterator cbegin() const { return begin(); }
	iterator end() { return statements.end(); }
	const_iterator end() const { return statements.end(); }
	const_iterator cend() const { return statements.end(); }
	
	Statement* operator[](size_t index) { return statements[index]; }
	const Statement* operator[](size_t index) const { return const_cast<SequenceStatement*>(this)->operator[](index); }
	Statement* front() { return statements.front(); }
	const Statement* front() const { return const_cast<SequenceStatement*>(this)->front(); }
	Statement* back() { return statements.back(); }
	const Statement* back() const { return const_cast<SequenceStatement*>(this)->back(); }
	size_t size() const { return statements.size(); }
	
	Statement* replace(iterator iter, NOT_NULL(Statement) newStatement);
	Statement* nullify(iterator iter) { return replace(iter, statements.getPool().allocate<NoopStatement>()); }
	
	virtual void replaceChild(NOT_NULL(Statement) child, NOT_NULL(Statement) newChild) override;
	void pushBack(NOT_NULL(Statement) statement);
	void takeAllFrom(SequenceStatement& statement);
};

class IfElseStatement final : public Statement
{
	Statement* ifBody;
	Statement* elseBody;
	
protected:
	virtual void dropAllStatementReferences() override;
	
public:
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == IfElse;
	}
	
	IfElseStatement(NOT_NULL(Expression) condition, NOT_NULL(Statement) ifBody, Statement* elseBody = nullptr)
	: Statement(IfElse, 1), ifBody(nullptr), elseBody(nullptr)
	{
		setCondition(condition);
		setIfBody(ifBody);
		setElseBody(elseBody);
	}
	
	NOT_NULL(Statement) getIfBody() { return ifBody; }
	NOT_NULL(const Statement) getIfBody() const { return &*ifBody; }
	Statement* getElseBody() { return elseBody; }
	const Statement* getElseBody() const { return elseBody; }
	
	virtual void replaceChild(NOT_NULL(Statement) child, NOT_NULL(Statement) newChild) override;
	Statement* setIfBody(NOT_NULL(Statement) ifBody);
	Statement* setElseBody(Statement* statement);
	
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
	Statement* loopBody;
	
protected:
	virtual void dropAllStatementReferences() override;
	
public:
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == Loop;
	}
	
	LoopStatement(NOT_NULL(Expression) condition, ConditionPosition position, NOT_NULL(Statement) body)
	: Statement(Loop, 1), position(position), loopBody(nullptr)
	{
		setCondition(condition);
		setLoopBody(body);
	}
	
	ConditionPosition getPosition() const { return position; }
	void setPosition(ConditionPosition condPos) { position = condPos; }
	
	virtual void replaceChild(NOT_NULL(Statement) child, NOT_NULL(Statement) newChild) override;
	NOT_NULL(Statement) getLoopBody() { return loopBody; }
	NOT_NULL(const Statement) getLoopBody() const { return &*loopBody; }
	Statement* setLoopBody(NOT_NULL(Statement) statement);
	
	OPERAND_GET_SET(Condition, 0)
	void discardCondition() { getOperandUse(0).setUse(nullptr); }
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
	virtual void replaceChild(NOT_NULL(Statement) child, NOT_NULL(Statement) newChild) override;
	
	using ExpressionUser::getOperand;
	using ExpressionUser::setOperand;
	
	// OPERAND_GET_SET assumes operands that are never null, but this one can be.
	Expression* getOperand() { return llvm::cast_or_null<Expression>(getOperand(0)); }
	const Expression* getOperand() const { return llvm::cast_or_null<Expression>(getOperand(0)); }
	void setOperand(Expression* op) { getOperandUse(0).setUse(op); }
	void discardExpression() { setOperand(nullptr); }
};

#endif /* fcd__ast_statements_h */
