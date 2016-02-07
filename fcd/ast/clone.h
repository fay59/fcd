//
// clone.h
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

#ifndef fcd__ast_clone_h
#define fcd__ast_clone_h

#include "dumb_allocator.h"
#include "visitor.h"

#include <unordered_map>

class ExpressionCloneVisitor : protected ExpressionVisitor
{
	DumbAllocator& pool;
	std::unordered_map<Expression*, Expression*> cloned;
	
protected:
	Expression* result;
	
	virtual void visitUnary(UnaryOperatorExpression* unary) override;
	virtual void visitNAry(NAryOperatorExpression* nary) override;
	virtual void visitTernary(TernaryExpression* ternary) override;
	virtual void visitNumeric(NumericExpression* numeric) override;
	virtual void visitToken(TokenExpression* token) override;
	virtual void visitCall(CallExpression* call) override;
	virtual void visitCast(CastExpression* cast) override;
	virtual void visitAggregate(AggregateExpression* agg) override;
	virtual void visitSubscript(SubscriptExpression* subscript) override;
	virtual void visitAssembly(AssemblyExpression* assembly) override;
	
public:
	inline ExpressionCloneVisitor(DumbAllocator& pool)
	: pool(pool), result(nullptr)
	{
	}
	
	static Expression* clone(DumbAllocator& pool, Expression* that);
	Expression* clone(Expression* that);
	
	virtual ~ExpressionCloneVisitor() = default;
};

#endif /* fcd__ast_clone_h */
