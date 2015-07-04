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

struct Expression;

struct Statement
{
	enum StatementType
	{
		Sequence, IfElse, Expr
	};
	
	void dump() const;
	virtual void print(llvm::raw_ostream& os, unsigned indent = 0) const = 0;
	virtual StatementType getType() const = 0;
};

struct SequenceNode : public Statement
{
	Statement** nodes;
	size_t count;
	
	static bool classof(const Statement* node)
	{
		return node->getType() == Sequence;
	}
	
	inline SequenceNode(Statement** nodes, size_t count) : nodes(nodes), count(count)
	{
	}
	
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
		Value, UnaryOperator, BinaryOperator
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

#endif /* ast_nodes_cpp */
