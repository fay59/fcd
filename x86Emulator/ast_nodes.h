//
//  ast_nodes.hpp
//  x86Emulator
//
//  Created by Félix on 2015-07-03.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#ifndef ast_nodes_cpp
#define ast_nodes_cpp

#include "dumb_allocator.h"
#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/CFG.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <algorithm>
#include <string>
#include <unordered_map>

#pragma mark - Expressions
struct Expression
{
	enum ExpressionType
	{
		Value, Token, UnaryOperator, NAryOperator
	};
	
	void dump() const;
	virtual void print(llvm::raw_ostream& os) const = 0;
	virtual ExpressionType getType() const = 0;
	
	virtual bool isReferenceEqual(const Expression* that) const = 0;
};

struct UnaryOperatorExpression : public Expression
{
	enum UnaryOperatorType : unsigned
	{
		Min = 0,
		
		// The SSA form ensures that we will never need a distinction between prefix and postfix increment/decrement.
		// That's why there's only one of each. We will, however, prefer the prefix version because postfix ++ and --
		// are the only postfix unary operators.
		Increment = Min, Decrement,
		LogicalNegate,
		Max
	};
	
	UnaryOperatorType type;
	Expression* operand;
	
	static inline bool classof(const Expression* node)
	{
		return node->getType() == UnaryOperator;
	}
	
	inline UnaryOperatorExpression(UnaryOperatorType type, Expression* operand)
	: type(type), operand(operand)
	{
	}
	
	virtual void print(llvm::raw_ostream& os) const override;
	virtual inline ExpressionType getType() const override { return UnaryOperator; }
	
	virtual inline bool isReferenceEqual(const Expression* that) const override
	{
		if (auto unaryThat = llvm::dyn_cast<UnaryOperatorExpression>(that))
		{
			return operand->isReferenceEqual(unaryThat->operand);
		}
		return false;
	}
};

struct NAryOperatorExpression : public Expression
{
	enum NAryOperatorType : unsigned
	{
		Min = UnaryOperatorExpression::Max,
		
		Multiply = Min, Divide, Modulus,
		Add, Subtract,
		ShiftLeft, ShiftRight,
		SmallerThan, SmallerOrEqualTo, GreaterThan, GreaterOrEqualTo,
		Equal, NotEqual,
		BitwiseAnd,
		BitwiseXor,
		BitwiseOr,
		ShortCircuitAnd,
		ShortCircuitOr,
		Max
	};
	
	NAryOperatorType type;
	PooledDeque<Expression*> operands;
	
	static inline bool classof(const Expression* node)
	{
		return node->getType() == NAryOperator;
	}
	
	inline NAryOperatorExpression(DumbAllocator& pool, NAryOperatorType type)
	: type(type), operands(pool)
	{
	}
	
	template<typename... TExpressionType>
	inline NAryOperatorExpression(DumbAllocator& pool, NAryOperatorType type, TExpressionType... expressions)
	: NAryOperatorExpression(pool, type)
	{
		addOperand(expressions...);
	}
	
	template<typename... TExpressionType>
	void addOperand(Expression* expression, TExpressionType... expressions)
	{
		addOperand(expression);
		addOperand(expressions...);
	}
	
	void addOperand(Expression* expression);
	
	virtual void print(llvm::raw_ostream& os) const override;
	virtual inline ExpressionType getType() const override { return NAryOperator; }
	
	virtual inline bool isReferenceEqual(const Expression* that) const override
	{
		if (auto naryThat = llvm::dyn_cast<NAryOperatorExpression>(that))
		{
			if (type == naryThat->type)
			{
				return std::equal(operands.cbegin(), operands.cend(), naryThat->operands.cbegin());
			}
		}
		return false;
	}
	
private:
	void print(llvm::raw_ostream& os, Expression* expression) const;
};

struct TokenExpression : public Expression
{
	static TokenExpression* trueExpression;
	static TokenExpression* falseExpression;
	
	const char* token;
	
	static inline bool classof(const Expression* node)
	{
		return node->getType() == Token;
	}
	
	inline TokenExpression(const char* token)
	: token(token)
	{
	}
	
	inline TokenExpression(DumbAllocator& pool, const std::string& token)
	: TokenExpression(pool.copy(token.c_str(), token.length() + 1))
	{
	}
	
	TokenExpression(DumbAllocator& pool, size_t integralValue);
	
	virtual void print(llvm::raw_ostream& os) const override;
	virtual inline ExpressionType getType() const override { return Token; }
	
	virtual inline bool isReferenceEqual(const Expression* that) const override
	{
		if (auto token = llvm::dyn_cast<TokenExpression>(that))
		{
			return this->token == token->token;
		}
		return false;
	}
};

#pragma mark - Temporary nodes
// (should be excluded from final result)
struct ValueExpression : public Expression
{
	llvm::Value* value;
	
	static inline bool classof(const Expression* node)
	{
		return node->getType() == Value;
	}
	
	inline explicit ValueExpression(llvm::Value& value) : value(&value)
	{
	}
	
	virtual void print(llvm::raw_ostream& os) const override;
	virtual inline ExpressionType getType() const override { return Value; }
	
	virtual inline bool isReferenceEqual(const Expression* that) const override
	{
		if (auto value = llvm::dyn_cast<ValueExpression>(that))
		{
			return this->value == value->value;
		}
		return false;
	}
};

#pragma mark - Statements

struct Statement
{
	enum StatementType
	{
		Sequence, IfElse, Loop, Expr, Keyword, Declaration, Assignment
	};
	
	void dump() const;
	virtual void print(llvm::raw_ostream& os, unsigned indent = 0) const = 0;
	virtual StatementType getType() const = 0;
};

struct SequenceNode : public Statement
{
	PooledDeque<Statement*> statements;
	
	static inline bool classof(const Statement* node)
	{
		return node->getType() == Sequence;
	}
	
	inline SequenceNode(DumbAllocator& pool)
	: statements(pool)
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
	
	static inline bool classof(const Statement* node)
	{
		return node->getType() == IfElse;
	}
	
	inline IfElseNode(Expression* condition, Statement* ifBody, Statement* elseBody = nullptr)
	: condition(condition), ifBody(ifBody), elseBody(elseBody)
	{
		assert(condition != nullptr);
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
	
	static inline bool classof(const Statement* node)
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

struct KeywordNode : public Statement
{
	static inline bool classof(const Statement* node)
	{
		return node->getType() == Keyword;
	}
	
	static KeywordNode* breakNode;
	
	const char* name;
	const char* operand;
	
	inline KeywordNode(const char* name, const char* operand = nullptr)
	: name(name), operand(operand)
	{
	}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline StatementType getType() const override { return Keyword; }
};

struct ExpressionNode : public Statement
{
	Expression* expression;
	
	static inline bool classof(const Statement* node)
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

struct DeclarationNode : public Statement
{
	TokenExpression* type;
	TokenExpression* name;
	const char* comment;
	size_t orderHint; // This field helps order declarations when they must be printed.
	
	static inline bool classof(const Statement* node)
	{
		return node->getType() == Declaration;
	}
	
	inline DeclarationNode(TokenExpression* type, TokenExpression* name, const char* comment = nullptr)
	: type(type), name(name), comment(comment), orderHint(0)
	{
	}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline StatementType getType() const override { return Declaration; }
};

struct AssignmentNode : public Statement
{
	Expression* left;
	Expression* right;
	
	static inline bool classof(const Statement* node)
	{
		return node->getType() == Assignment;
	}
	
	inline AssignmentNode(Expression* left, Expression* right)
	: left(left), right(right)
	{
	}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline StatementType getType() const override { return Assignment; }
};

bool LoopNode::isEndless() const
{
	return condition == TokenExpression::trueExpression;
}

#pragma mark - Function

// The FunctionNode's lifetime is tied to the lifetime of its memory pool (because the lifetime of almost everything it
// contains is), but it is not itself intended to be allocated through the DumbAllocator interface. FunctionNode needs
// more complex data structures that I have no intention of replicating à la PooledDeque, and thus has a non-trivial
// destructor.
class FunctionNode
{
	DumbAllocator& pool;
	llvm::Function& function;
	std::unordered_map<llvm::Value*, DeclarationNode*> declarationMap;
	std::unordered_map<llvm::Value*, TokenExpression*> valueMap;
	
	Expression* getNodeValue(llvm::Value* value);
	DeclarationNode* getDeclaration(llvm::PHINode* value);
	
public:
	SequenceNode* body;
	
	inline FunctionNode(DumbAllocator& pool, llvm::Function& fn)
	: pool(pool), function(fn)
	{
		body = nullptr; // manually assign this one
	}
	
	SequenceNode* basicBlockToStatement(llvm::BasicBlock& bb);
	
	void print(llvm::raw_ostream& os) const;
	void dump() const;
};

#endif /* ast_nodes_cpp */
