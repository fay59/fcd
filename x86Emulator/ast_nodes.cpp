//
//  ast_nodes.cpp
//  x86Emulator
//
//  Created by Félix on 2015-07-03.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#include "ast_nodes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Constants.h>
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <iostream>
#include <limits>
#include <string>

using namespace llvm;
using namespace std;

namespace
{
	template<typename T, size_t N>
	constexpr size_t countof(const T (&)[N])
	{
		return N;
	}
	
	inline string indent(unsigned times)
	{
		return string(times, '\t');
	}
	
	inline string toString(size_t integer)
	{
		string result;
		raw_string_ostream(result) << integer;
		return result;
	}
	
	inline void printTypeAsC(raw_ostream& os, Type* type)
	{
		if (type->isVoidTy())
		{
			os << "void";
			return;
		}
		if (type->isIntegerTy())
		{
			// HACKHACK: this will not do if we ever want to differentiate signed and unsigned values
			os << "int" << type->getIntegerBitWidth() << "_t";
			return;
		}
		if (type->isPointerTy())
		{
			// HACKHACK: this will not do once LLVM gets rid of pointer types
			printTypeAsC(os, type->getPointerElementType());
			os << '*';
			return;
		}
		llvm_unreachable("implement me");
	}
	
	inline string toString(Type* type)
	{
		string result;
		raw_string_ostream ss(result);
		printTypeAsC(ss, type);
		ss.flush();
		return result;
	}
	
	string operatorName[] = {
		[UnaryOperatorExpression::Increment] = "++",
		[UnaryOperatorExpression::Decrement] = "--",
		[UnaryOperatorExpression::LogicalNegate] = "!",
		[NAryOperatorExpression::Multiply] = "*",
		[NAryOperatorExpression::Divide] = "/",
		[NAryOperatorExpression::Modulus] = "%",
		[NAryOperatorExpression::Add] = "+",
		[NAryOperatorExpression::Subtract] = "-",
		[NAryOperatorExpression::ShiftLeft] = "<<",
		[NAryOperatorExpression::ShiftRight] = ">>",
		[NAryOperatorExpression::SmallerThan] = "<",
		[NAryOperatorExpression::SmallerOrEqualTo] = "<=",
		[NAryOperatorExpression::GreaterThan] = ">",
		[NAryOperatorExpression::GreaterOrEqualTo] = ">=",
		[NAryOperatorExpression::Equal] = "==",
		[NAryOperatorExpression::NotEqual] = "!=",
		[NAryOperatorExpression::BitwiseAnd] = "&",
		[NAryOperatorExpression::BitwiseXor] = "^",
		[NAryOperatorExpression::BitwiseOr] = "|",
		[NAryOperatorExpression::ShortCircuitAnd] = "&&",
		[NAryOperatorExpression::ShortCircuitOr] = "||",
	};
	
	unsigned operatorPrecedence[] = {
		[UnaryOperatorExpression::Increment] = 1,
		[UnaryOperatorExpression::Decrement] = 1,
		[UnaryOperatorExpression::LogicalNegate] = 2,
		[NAryOperatorExpression::Multiply] = 3,
		[NAryOperatorExpression::Divide] = 3,
		[NAryOperatorExpression::Modulus] = 3,
		[NAryOperatorExpression::Add] = 4,
		[NAryOperatorExpression::Subtract] = 4,
		[NAryOperatorExpression::ShiftLeft] = 5,
		[NAryOperatorExpression::ShiftRight] = 5,
		[NAryOperatorExpression::SmallerThan] = 6,
		[NAryOperatorExpression::SmallerOrEqualTo] = 6,
		[NAryOperatorExpression::GreaterThan] = 6,
		[NAryOperatorExpression::GreaterOrEqualTo] = 6,
		[NAryOperatorExpression::Equal] = 7,
		[NAryOperatorExpression::NotEqual] = 7,
		[NAryOperatorExpression::BitwiseAnd] = 8,
		[NAryOperatorExpression::BitwiseXor] = 9,
		[NAryOperatorExpression::BitwiseOr] = 10,
		[NAryOperatorExpression::ShortCircuitAnd] = 11,
		[NAryOperatorExpression::ShortCircuitOr] = 12,
	};
	
	static_assert(countof(operatorName) == NAryOperatorExpression::Max, "Incorrect number of operator name entries");
	static_assert(countof(operatorPrecedence) == NAryOperatorExpression::Max, "Incorrect number of operator precedence entries");
	
	constexpr char nl = '\n';
	
	BreakNode breakNode;
	TokenExpression trueExpression("true");
	TokenExpression falseExpression("false");
}

#pragma mark - Statements

void Statement::dump() const
{
	raw_os_ostream rerr(cerr);
	print(rerr);
}

void SequenceNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent) << '{' << nl;
	for (size_t i = 0; i < statements.size(); i++)
	{
		statements[i]->print(os, indent + 1);
	}
	os << ::indent(indent) << '}' << nl;
}

void IfElseNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent) << "if ";
	condition->print(os);
	os << nl;
	
	ifBody->print(os, indent + !isa<SequenceNode>(ifBody));
	if (elseBody != nullptr)
	{
		os << ::indent(indent) << "else" << nl;
		elseBody->print(os, indent + !isa<SequenceNode>(elseBody));
	}
}

LoopNode::LoopNode(Statement* body)
: condition(TokenExpression::trueExpression), position(LoopNode::PreTested), loopBody(body)
{
}

void LoopNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	if (position == PreTested)
	{
		os << ::indent(indent) << "while ";
		condition->print(os);
		os << nl;
		loopBody->print(os, indent + !isa<SequenceNode>(loopBody));
	}
	else
	{
		assert(position == PostTested);
		os << ::indent(indent) << "do" << nl;
		loopBody->print(os, indent + !isa<SequenceNode>(loopBody));
		os << ::indent(indent) << "while ";
		condition->print(os);
		os << nl;
	}
}

BreakNode* BreakNode::breakNode = &::breakNode;

void BreakNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent) << "break;" << nl;
}

void ExpressionNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent);
	if (auto valueNode = dyn_cast<ValueExpression>(expression))
	{
		valueNode->value->print(os);
	}
	else
	{
		expression->print(os);
	}
	os << ';' << nl;
}

void DeclarationNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent);
	type->print(os);
	os << ' ';
	name->print(os);
	os << ';';
	if (comment != nullptr)
	{
		os << " // " << comment;
	}
	os << nl;
}

void AssignmentNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent);
	left->print(os);
	os << " = ";
	right->print(os);
	os << ';' << nl;
}

#pragma mark - Expressions

void ValueExpression::print(llvm::raw_ostream &os) const
{
	os << '(';
	value->printAsOperand(os);
	os << ')';
}

void UnaryOperatorExpression::print(llvm::raw_ostream &os) const
{
	os << (type < Max ? operatorName[type] : "<bad unary>");
	operand->print(os);
}

void NAryOperatorExpression::addOperand(Expression *expression)
{
	if (auto asNAry = dyn_cast<NAryOperatorExpression>(expression))
	{
		if (asNAry->type == type)
		{
			operands.push_back(asNAry->operands.begin(), asNAry->operands.end());
			return;
		}
	}
	operands.push_back(expression);
}

void NAryOperatorExpression::print(llvm::raw_ostream &os) const
{
	assert(operands.size() > 0);
	
	auto iter = operands.begin();
	print(os, *iter);
	++iter;
	for (; iter != operands.end(); ++iter)
	{
		os << ' ' << (type < Max ? operatorName[type] : "<bad operator>") << ' ';
		print(os, *iter);
	}
}

void NAryOperatorExpression::print(raw_ostream& os, Expression* expr) const
{
	bool parenthesize = false;
	if (auto asNAry = dyn_cast<NAryOperatorExpression>(expr))
	{
		parenthesize = operatorPrecedence[asNAry->type] > operatorPrecedence[type];
	}
	else if (auto asUnary = dyn_cast<UnaryOperatorExpression>(expr))
	{
		parenthesize = operatorPrecedence[asUnary->type] > operatorPrecedence[type];
	}
	
	if (parenthesize) os << '(';
	expr->print(os);
	if (parenthesize) os << ')';
}

TokenExpression* TokenExpression::trueExpression = &::trueExpression;
TokenExpression* TokenExpression::falseExpression = &::falseExpression;

TokenExpression::TokenExpression(DumbAllocator& pool, size_t integralValue)
: TokenExpression(pool, toString(integralValue))
{
}

void TokenExpression::print(llvm::raw_ostream &os) const
{
	os << token;
}

#pragma mark - Functions

DeclarationNode* FunctionNode::getDeclaration(llvm::PHINode *value)
{
	auto iter = declarationMap.find(value);
	if (iter != declarationMap.end())
	{
		return iter->second;
	}
	
	auto type = pool.allocate<TokenExpression>(pool, toString(value->getType()));
	auto name = pool.allocate<TokenExpression>(pool, "phi" + toString(declarationMap.size()));
	auto decl = pool.allocate<DeclarationNode>(type, name);
	decl->orderHint = numeric_limits<size_t>::max() - declarationMap.size();
	declarationMap.insert({value, decl});
	return decl;
}

Expression* FunctionNode::getNodeValue(llvm::Value *value)
{
	auto iter = valueMap.find(value);
	if (iter != valueMap.end())
	{
		return iter->second;
	}
	
	TokenExpression* result = nullptr;
	if (auto constantInt = dyn_cast<ConstantInt>(value))
	{
		result = pool.allocate<TokenExpression>(pool, toString(constantInt->getLimitedValue()));
	}
	
	valueMap.insert({value, result});
	return result;
}

SequenceNode* FunctionNode::basicBlockToStatement(llvm::BasicBlock &bb)
{
	SequenceNode* node = pool.allocate<SequenceNode>(pool);
	// Translate instructions.
	for (Instruction& inst : bb)
	{
		// Remove branch instructions at this step. Use basic blocks to figure out the conditions.
		if (!isa<BranchInst>(inst) && !isa<SwitchInst>(inst))
		{
			Expression* value = pool.allocate<ValueExpression>(inst);
			ExpressionNode* expressionNode = pool.allocate<ExpressionNode>(value);
			node->statements.push_back(expressionNode);
		}
	}
	
	// Add phi value assignments.
	for (BasicBlock* successor : successors(&bb))
	{
		for (auto phiIter = successor->begin(); PHINode* phi = dyn_cast<PHINode>(phiIter); phiIter++)
		{
			auto declaration = getDeclaration(phi);
			auto phiValue = getNodeValue(phi->getIncomingValueForBlock(&bb));
			auto assignment = pool.allocate<AssignmentNode>(declaration->name, phiValue);
			node->statements.push_back(assignment);
		}
	}
	
	return node;
}

void FunctionNode::print(llvm::raw_ostream &os) const
{
	auto type = function.getFunctionType();
	printTypeAsC(os, type->getReturnType());
	os << ' ' << function.getName() << '(';
	auto iter = function.arg_begin();
	if (iter != function.arg_end())
	{
		printTypeAsC(os, iter->getType());
		os << ' ' << iter->getName();
		while (iter != function.arg_end())
		{
			os << ", ";
			printTypeAsC(os, iter->getType());
			os << ' ' << iter->getName();
			iter++;
		}
	}
	else
	{
		os << "void";
	}
	os << ")\n{\n";
	
	// print declarations
	vector<Statement*> decls;
	for (const auto& pair : declarationMap)
	{
		decls.push_back(pair.second);
	}
	
	sort(decls.begin(), decls.end(), [](Statement* a, Statement* b)
	{
		return cast<DeclarationNode>(a)->orderHint < cast<DeclarationNode>(b)->orderHint;
	});
	
	for (auto declaration : decls)
	{
		declaration->print(os, 1);
	}
	
	os << nl;
	// print body
	for (auto statement : body->statements)
	{
		statement->print(os, 1);
	}
	
	os << "}\n";
}

void FunctionNode::dump() const
{
	raw_os_ostream rerr(cerr);
	print(rerr);
}
