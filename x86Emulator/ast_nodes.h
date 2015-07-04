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

struct AstNode
{
	enum AstNodeType
	{
		Value, UnaryOperator, BinaryOperator, Sequence, IfElse, Goto
	};
	
	void dump() const;
	virtual void print(llvm::raw_ostream& os, unsigned indent = 0) const = 0;
	virtual AstNodeType getType() const = 0;
};

struct SequenceNode : public AstNode
{
	AstNode** nodes;
	size_t count;
	
	static bool classof(const AstNode* node)
	{
		return node->getType() == Sequence;
	}
	
	inline SequenceNode(AstNode** nodes, size_t count) : nodes(nodes), count(count)
	{
	}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline AstNodeType getType() const override { return Sequence; }
};

struct IfElseNode : public AstNode
{
	AstNode* condition;
	AstNode* ifBody;
	AstNode* elseBody;
	
	static bool classof(const AstNode* node)
	{
		return node->getType() == IfElse;
	}
	
	inline IfElseNode(AstNode* condition, AstNode* ifBody, AstNode* elseBody = nullptr)
	: condition(condition), ifBody(ifBody), elseBody(elseBody)
	{
	}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline AstNodeType getType() const override { return IfElse; }
};

#pragma mark - Expressions
// FIXME: might want to have an Expression root class at some point
struct UnaryOperatorNode : public AstNode
{
	enum UnaryOperatorType : unsigned
	{
		LogicalNegate,
		Max
	};
	
	UnaryOperatorType type;
	AstNode* operand;
	
	static bool classof(const AstNode* node)
	{
		return node->getType() == Sequence;
	}
	
	inline UnaryOperatorNode(UnaryOperatorType type, AstNode* operand)
	: type(type), operand(operand)
	{
	}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline AstNodeType getType() const override { return UnaryOperator; }
};

struct BinaryOperatorNode : public AstNode
{
	enum BinaryOperatorType : unsigned
	{
		ShortCircuitAnd, ShortCircuitOr,
		Max
	};
	
	BinaryOperatorType type;
	AstNode* left;
	AstNode* right;
	
	static bool classof(const AstNode* node)
	{
		return node->getType() == Sequence;
	}
	
	inline BinaryOperatorNode(BinaryOperatorType type, AstNode* left, AstNode* right)
	: type(type), left(left), right(right)
	{
	}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline AstNodeType getType() const override { return BinaryOperator; }
};

#pragma mark - Temporary nodes
// (should be excluded from final result)
struct ValueNode : public AstNode
{
	llvm::Value* value;
	
	static bool classof(const AstNode* node)
	{
		return node->getType() == Value;
	}
	
	inline explicit ValueNode(llvm::Value& value) : value(&value)
	{
	}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline AstNodeType getType() const override { return Value; }
};

struct GotoNode : public AstNode
{
	llvm::BasicBlock* target;
	
	static bool classof(const AstNode* node)
	{
		return node->getType() == Goto;
	}
	
	inline explicit GotoNode(llvm::BasicBlock& target) : target(&target)
	{
	}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline AstNodeType getType() const override { return Goto; }
};

#endif /* ast_nodes_cpp */
