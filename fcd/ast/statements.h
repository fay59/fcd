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
	template<bool B, typename T>
	using OptionallyConst = typename std::conditional<B, typename std::add_const<T>::type, typename std::remove_const<T>::type>::type;
	
	Statement* owner;
	Statement* first;
	Statement* last;
	
public:
	template<bool IsConst>
	class StatementIterator : public std::iterator<std::bidirectional_iterator_tag, OptionallyConst<IsConst, Statement>*>
	{
		typedef OptionallyConst<IsConst, Statement>* StmtType;
		StmtType current;
		
	public:
		StatementIterator(std::nullptr_t)
		: current(nullptr)
		{
		}
		
		explicit StatementIterator(StmtType statement)
		: current(statement)
		{
		}
		
		StatementIterator(const StatementIterator&) = default;
		StatementIterator(StatementIterator&&) = default;
		
		auto operator*() { return current; }
		
		template<bool B>
		bool operator==(const StatementIterator<B>& that) const { return current == that.current; }
		
		template<bool B>
		bool operator!=(const StatementIterator<B>& that) const { return !(*this == that); }
		
		inline StatementIterator& operator++();
		inline StatementIterator& operator--();
		
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
	
	typedef StatementIterator<false> iterator;
	typedef StatementIterator<true> const_iterator;
	
	explicit StatementList(Statement* parent)
	: owner(parent), first(nullptr), last(nullptr)
	{
	}
	
	StatementList(Statement* parent, StatementList&& that);
	StatementList(Statement* parent, std::initializer_list<Statement*> statements);
	
	Statement* parent() { return owner; }
	Statement* front() { return first; }
	Statement* back() { return last; }
	
	Statement* pop_front();
	Statement* pop_back();
	
	bool empty() const { return first == nullptr; }
	Statement* single() { return first == last ? first : nullptr; }
	const Statement* single() const { return first == last ? first : nullptr; }
	bool multiple() const { return first != last; }
	
	iterator begin() { return iterator(first); }
	const_iterator begin() const { return const_iterator(first); }
	const_iterator cbegin() const { return begin(); }
	iterator end() { return iterator(nullptr); }
	const_iterator end() const { return const_iterator(nullptr); }
	const_iterator cend() const { return end(); }
	
	StatementList& operator=(StatementList&& that);
	
	static void insert(NOT_NULL(Statement) location, NOT_NULL(Statement) statement);
	static void insert(NOT_NULL(Statement) location, StatementList&& list);
	void insert(iterator iter, NOT_NULL(Statement) statement);
	void insert(iterator iter, StatementList&& that);
	
	void push_front(NOT_NULL(Statement) statement);
	void push_front(StatementList&& that);
	void push_back(NOT_NULL(Statement) statement);
	void push_back(StatementList&& that);
	
	static void erase(NOT_NULL(Statement) statement);
	iterator erase(iterator iter);
	
	void clear();
	
	void print(llvm::raw_ostream& os) const;
	void dump() const;
};

// Temporary statement list, destroyed at the end of the scope like an ExpressionReference.
class StatementReference
{
	StatementList list;
	
public:
	StatementReference()
	: list(nullptr)
	{
	}
	
	StatementReference(StatementList&& that)
	: list(nullptr, std::move(that))
	{
	}
	
	StatementReference(std::initializer_list<Statement*> statements)
	: list(nullptr, statements)
	{
	}
	
	StatementReference(StatementReference&& that)
	: list(nullptr, std::move(that.list))
	{
	}
	
	~StatementReference() { list.clear(); }
	
	StatementReference& operator=(StatementReference&& that)
	{
		list = std::move(that.list);
		return *this;
	}
	
	StatementList* operator->() { return &list; }
	const StatementList* operator->() const { return &list; }
	StatementList& operator*() { return *operator->(); }
	const StatementList& operator*() const { return *operator->(); }
	
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
	: ExpressionUser(type, allocatedUses), list(nullptr), previous(nullptr), next(nullptr)
	{
		assert(type >= StatementMin && type < StatementMax);
	}
	
	StatementList* getParentList() { return list; }
	Statement* getParent() { return list == nullptr ? nullptr : list->parent(); }
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
};

template<bool B>
inline StatementList::StatementIterator<B>& StatementList::StatementIterator<B>::operator++()
{
	current = current->next;
	return *this;
}

template<bool B>
inline StatementList::StatementIterator<B>& StatementList::StatementIterator<B>::operator--()
{
	current = current->previous;
	return *this;
}

#endif /* fcd__ast_statements_h */
