//
//  ast_nodes.hpp
//  x86Emulator
//
//  Created by Félix on 2015-07-03.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#ifndef ast_nodes_cpp
#define ast_nodes_cpp

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/CFG.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <string>

struct Expression;

struct Statement
{
	enum StatementType
	{
		Sequence, IfElse, Loop, Expr, Break
	};
	
	void dump() const;
	virtual void print(llvm::raw_ostream& os, unsigned indent = 0) const = 0;
	virtual StatementType getType() const = 0;
};

struct SequenceNode : public Statement
{
	Statement** nodes;
	size_t count;
	size_t allocated;
	
	static bool classof(const Statement* node)
	{
		return node->getType() == Sequence;
	}
	
	inline SequenceNode(Statement** nodes, size_t allocated, size_t count)
	: nodes(nodes), count(count), allocated(allocated)
	{
	}
	
	bool append(Statement* statement);
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline StatementType getType() const override { return Sequence; }
};

struct IfElseNode : public Statement
{
	Expression* condition;
	Statement* ifBody;
	Statement* elseBody;
	
	static bool classof(const Statement* node)
	{
		return node->getType() == IfElse;
	}
	
	inline IfElseNode(Expression* condition, Statement* ifBody, Statement* elseBody = nullptr)
	: condition(condition), ifBody(ifBody), elseBody(elseBody)
	{
	}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline StatementType getType() const override { return IfElse; }
};

struct LoopNode : public Statement
{
	enum ConditionPosition {
		PreTested, // while
		PostTested, // do ... while
	};
	
	Expression* condition;
	ConditionPosition position;
	Statement* loopBody;
	
	static bool classof(const Statement* node)
	{
		return node->getType() == Loop;
	}
	
	LoopNode(Statement* body); // creates a `while (true)`
	
	inline LoopNode(Expression* condition, ConditionPosition position, Statement* body)
	: condition(condition), position(position), loopBody(body)
	{
	}
	
	inline bool isEndless() const;
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline StatementType getType() const override { return Loop; }
};

struct BreakNode : public Statement
{
	static bool classof(const Statement* node)
	{
		return node->getType() == Loop;
	}
	
	static BreakNode* breakNode;
	
	inline BreakNode() {}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline StatementType getType() const override { return Break; }
};

struct ExpressionNode : public Statement
{
	Expression* expression;
	
	static bool classof(const Statement* node)
	{
		return node->getType() == Expr;
	}
	
	inline ExpressionNode(Expression* expr)
	: expression(expr)
	{
	}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline StatementType getType() const override { return Expr; }
};

#pragma mark - Expressions
struct Expression
{
	enum ExpressionType
	{
		Value, Token, UnaryOperator, BinaryOperator
	};
	
	void dump() const;
	virtual void print(llvm::raw_ostream& os) const = 0;
	virtual ExpressionType getType() const = 0;
};

struct UnaryOperatorExpression : public Expression
{
	enum UnaryOperatorType : unsigned
	{
		LogicalNegate,
		Max
	};
	
	UnaryOperatorType type;
	Expression* operand;
	
	static bool classof(const Expression* node)
	{
		return node->getType() == UnaryOperator;
	}
	
	inline UnaryOperatorExpression(UnaryOperatorType type, Expression* operand)
	: type(type), operand(operand)
	{
	}
	
	virtual void print(llvm::raw_ostream& os) const override;
	virtual inline ExpressionType getType() const override { return UnaryOperator; }
};

struct BinaryOperatorExpression : public Expression
{
	enum BinaryOperatorType : unsigned
	{
		ShortCircuitAnd, ShortCircuitOr,
		Equality,
		Max
	};
	
	BinaryOperatorType type;
	Expression* left;
	Expression* right;
	
	static bool classof(const Expression* node)
	{
		return node->getType() == BinaryOperator;
	}
	
	inline BinaryOperatorExpression(BinaryOperatorType type, Expression* left, Expression* right)
	: type(type), left(left), right(right)
	{
	}
	
	virtual void print(llvm::raw_ostream& os) const override;
	virtual inline ExpressionType getType() const override { return BinaryOperator; }
};

struct TokenExpression : public Expression
{
	static TokenExpression* trueExpression;
	static TokenExpression* falseExpression;
	
	const char* token;
	
	static bool classof(const Expression* node)
	{
		return node->getType() == Token;
	}
	
	inline TokenExpression(const char* token)
	: token(token)
	{
	}
	
	virtual void print(llvm::raw_ostream& os) const override;
	virtual inline ExpressionType getType() const override { return Token; }
};

#pragma mark - Temporary nodes
// (should be excluded from final result)
struct ValueExpression : public Expression
{
	llvm::Value* value;
	
	static bool classof(const Expression* node)
	{
		return node->getType() == Value;
	}
	
	inline explicit ValueExpression(llvm::Value& value) : value(&value)
	{
	}
	
	virtual void print(llvm::raw_ostream& os) const override;
	virtual inline ExpressionType getType() const override { return Value; }
};

bool LoopNode::isEndless() const
{
	return condition == TokenExpression::trueExpression;
}

#endif /* ast_nodes_cpp */
