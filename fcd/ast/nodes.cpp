//
// nodes.cpp
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

#include "nodes.h"
#include "function.h"
#include "visitor.h"
#include "print.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <cstring>
#include <iostream>

using namespace llvm;
using namespace std;

namespace
{
	KeywordNode breakNode("break");
	TokenExpression trueExpression("true");
	TokenExpression falseExpression("false");
	TokenExpression undefExpression("__undefined");
}

#pragma mark - Statements

void Statement::dump() const
{
	raw_os_ostream rerr(cerr);
	print(rerr);
}

void Statement::printShort(raw_ostream& os) const
{
	StatementShortPrintVisitor print(os);
	const_cast<Statement&>(*this).visit(print);
}

void Statement::print(raw_ostream& os) const
{
	StatementPrintVisitor print(os);
	const_cast<Statement&>(*this).visit(print);
}

void SequenceNode::visit(StatementVisitor &visitor)
{
	visitor.visitSequence(this);
}

void IfElseNode::visit(StatementVisitor &visitor)
{
	visitor.visitIfElse(this);
}

LoopNode::LoopNode(Statement* body)
: LoopNode(TokenExpression::trueExpression, PreTested, body)
{
}

void LoopNode::visit(StatementVisitor &visitor)
{
	visitor.visitLoop(this);
}

KeywordNode* KeywordNode::breakNode = &::breakNode;

void KeywordNode::visit(StatementVisitor &visitor)
{
	visitor.visitKeyword(this);
}

void ExpressionNode::visit(StatementVisitor &visitor)
{
	visitor.visitExpression(this);
}

void DeclarationNode::visit(StatementVisitor &visitor)
{
	visitor.visitDeclaration(this);
}

void AssignmentNode::visit(StatementVisitor &visitor)
{
	visitor.visitAssignment(this);
}

#pragma mark - Expressions

void Expression::print(raw_ostream& os) const
{
	ExpressionPrintVisitor printer(os);
	const_cast<Expression&>(*this).visit(printer);
}

void Expression::dump() const
{
	raw_os_ostream rerr(cerr);
	print(rerr);
}

bool UnaryOperatorExpression::isReferenceEqual(const Expression *that) const
{
	if (auto unaryThat = llvm::dyn_cast<UnaryOperatorExpression>(that))
	if (unaryThat->type == type)
	{
		return operand->isReferenceEqual(unaryThat->operand);
	}
	return false;
}

void UnaryOperatorExpression::visit(ExpressionVisitor &visitor)
{
	visitor.visitUnary(this);
}

void NAryOperatorExpression::addOperand(Expression *expression)
{
	if (auto asNAry = dyn_cast<NAryOperatorExpression>(expression))
	if (asNAry->type == type)
	{
		operands.push_back(asNAry->operands.begin(), asNAry->operands.end());
		return;
	}
	operands.push_back(expression);
}

void NAryOperatorExpression::visit(ExpressionVisitor &visitor)
{
	visitor.visitNAry(this);
}

bool NAryOperatorExpression::isReferenceEqual(const Expression *that) const
{
	if (auto naryThat = llvm::dyn_cast<NAryOperatorExpression>(that))
	if (naryThat->type == type)
	{
		return std::equal(operands.cbegin(), operands.cend(), naryThat->operands.cbegin(), [](const Expression* a, const Expression* b)
		{
			return a->isReferenceEqual(b);
		});
	}
	return false;
}

void TernaryExpression::visit(ExpressionVisitor &visitor)
{
	visitor.visitTernary(this);
}

bool TernaryExpression::isReferenceEqual(const Expression *that) const
{
	if (auto ternary = llvm::dyn_cast<TernaryExpression>(that))
	{
		return ifTrue->isReferenceEqual(ternary->ifTrue) && ifFalse->isReferenceEqual(ternary->ifFalse);
	}
	return false;
}

void NumericExpression::visit(ExpressionVisitor &visitor)
{
	visitor.visitNumeric(this);
}

bool NumericExpression::isReferenceEqual(const Expression *that) const
{
	if (auto token = llvm::dyn_cast<NumericExpression>(that))
	{
		return this->ui64 == token->ui64;
	}
	return false;
}

TokenExpression* TokenExpression::trueExpression = &::trueExpression;
TokenExpression* TokenExpression::falseExpression = &::falseExpression;
TokenExpression* TokenExpression::undefExpression = &::undefExpression;

void TokenExpression::visit(ExpressionVisitor &visitor)
{
	visitor.visitToken(this);
}

bool TokenExpression::isReferenceEqual(const Expression *that) const
{
	if (auto token = llvm::dyn_cast<TokenExpression>(that))
	{
		return strcmp(this->token, token->token) == 0;
	}
	return false;
}

void CallExpression::visit(ExpressionVisitor &visitor)
{
	visitor.visitCall(this);
}

bool CallExpression::isReferenceEqual(const Expression *that) const
{
	if (auto thatCall = llvm::dyn_cast<CallExpression>(that))
	if (this->callee == thatCall->callee)
	{
		return std::equal(parameters.begin(), parameters.end(), thatCall->parameters.begin(), [](Expression* a, Expression* b)
		{
			return a->isReferenceEqual(b);
		});
	}
	return false;
}

void CastExpression::visit(ExpressionVisitor &visitor)
{
	visitor.visitCast(this);
}

bool CastExpression::isReferenceEqual(const Expression *that) const
{
	if (auto thatCast = llvm::dyn_cast<CastExpression>(that))
	{
		return type->isReferenceEqual(thatCast->type) && casted->isReferenceEqual(thatCast->casted);
	}
	return false;
}
