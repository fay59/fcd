//
// pass_simplifyconditions.h
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

#ifndef fcd__ast_pass_simplifyexpressions_h
#define fcd__ast_pass_simplifyexpressions_h

#include "pass.h"
#include "visitor.h"

class AstSimplifyExpressions : public AstFunctionPass, private ExpressionVisitor, private StatementVisitor
{
	Expression* result;
	Expression* simplify(Expression* expr);
	
	virtual void visitIfElse(IfElseNode* ifElse) override;
	virtual void visitLoop(LoopNode* loop) override;
	virtual void visitKeyword(KeywordNode* keyword) override;
	virtual void visitExpression(ExpressionNode* expression) override;
	virtual void visitAssignment(AssignmentNode* assignment) override;
	
	virtual void visitUnary(UnaryOperatorExpression* unary) override;
	virtual void visitNAry(NAryOperatorExpression* nary) override;
	virtual void visitTernary(TernaryExpression* ternary) override;
	virtual void visitNumeric(NumericExpression* numeric) override;
	virtual void visitToken(TokenExpression* token) override;
	virtual void visitCall(CallExpression* call) override;
	virtual void visitCast(CastExpression* cast) override;
	virtual void visitAggregate(AggregateExpression* cast) override;
	
protected:
	virtual void doRun(FunctionNode& fn) override;
	
public:
	AstSimplifyExpressions() = default;
	
	virtual const char* getName() const override;
};

#endif /* fcd__ast_pass_simplifyexpressions_h */
