//
// clone.cpp
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

#include "clone.h"
#include "llvm_warnings.h"
#include "visitor.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/ErrorHandling.h>
SILENCE_LLVM_WARNINGS_END()

#include <deque>
#include <unordered_map>

using namespace llvm;
using namespace std;

namespace
{
	class ExpressionCloneVisitor : public AstVisitor<ExpressionCloneVisitor, true, NOT_NULL(Expression)>
	{
		AstContext& context;
		unordered_map<const Expression*, Expression*> clones;
		
	public:
		ExpressionCloneVisitor(AstContext& context)
		: context(context)
		{
		}
		
		NOT_NULL(Expression) visit(const ExpressionUser& user)
		{
			if (auto expr = dyn_cast<Expression>(&user))
			{
				auto& clone = clones[expr];
				if (clone == nullptr)
				{
					clone = AstVisitor::visit(*expr);
				}
				return clone;
			}
			else
			{
				return AstVisitor::visit(user);
			}
		}
		
		NOT_NULL(Expression) visitUnaryOperator(const UnaryOperatorExpression& unary)
		{
			return context.unary(unary.getType(), visit(*unary.getOperand()));
		}
		
		NOT_NULL(Expression) visitNAryOperator(const NAryOperatorExpression& nary)
		{
			auto result = context.nary(nary.getType(), nary.operands_size());
			unsigned i = 0;
			for (const ExpressionUse& use : nary.operands())
			{
				result->setOperand(i, visit(*use.getUse()));
				++i;
			}
			return result;
		}
		
		NOT_NULL(Expression) visitTernary(const TernaryExpression& ternary)
		{
			return context.ternary(
				visit(*ternary.getCondition()),
				visit(*ternary.getTrueValue()),
				visit(*ternary.getFalseValue()));
		}
		
		NOT_NULL(Expression) visitNumeric(const NumericExpression& numeric)
		{
			return context.numeric(numeric.ui64);
		}
		
		NOT_NULL(Expression) visitToken(const TokenExpression& token)
		{
			return context.token(&*token.token);
		}
		
		NOT_NULL(Expression) visitCall(const CallExpression& call)
		{
			auto result = context.call(visit(*call.getCallee()), call.params_size());
			unsigned i = 0;
			for (const ExpressionUse& use : call.params())
			{
				result->setParameter(i, visit(*use.getUse()));
				++i;
			}
			return result;
		}
		
		NOT_NULL(Expression) visitCast(const CastExpression& cast)
		{
			NOT_NULL(Expression) clonedType = visit(*cast.getCastType());
			return context.cast(llvm::cast<TokenExpression>(clonedType), visit(*cast.getCastValue()));
		}
		
		NOT_NULL(Expression) visitAggregate(const AggregateExpression& agg)
		{
			auto result = context.aggregate(agg.operands_size());
			unsigned i = 0;
			for (const ExpressionUse& use : agg.operands())
			{
				result->setOperand(i, visit(*use.getUse()));
				++i;
			}
			return result;
		}
		
		NOT_NULL(Expression) visitSubscript(const SubscriptExpression& subscript)
		{
			return context.subscript(visit(*subscript.getPointer()), visit(*subscript.getIndex()));
		}
		
		NOT_NULL(Expression) visitAssembly(const AssemblyExpression& assembly)
		{
			auto copy = context.assembly(&*assembly.assembly);
			for (const char* param : assembly.parameterNames)
			{
				copy->addParameterName(param);
			}
			return copy;
		}
		
		NOT_NULL(Expression) visitAssignable(const AssignableExpression& assignable)
		{
			NOT_NULL(Expression) clonedType = visit(*assignable.getType());
			return context.assignable(cast<TokenExpression>(clonedType), &*assignable.prefix);
		}
		
		NOT_NULL(Expression) visitDefault(const ExpressionUser& user)
		{
			llvm_unreachable("unimplemented expression clone case");
		}
	};
	
	class StatementCloneVisitor : public AstVisitor<StatementCloneVisitor, true, Statement*>
	{
		AstContext& ctx;
		ExpressionCloneVisitor expressionCloner;
		
		void appendSequence(deque<NOT_NULL(Statement)>& into, const SequenceStatement& seq)
		{
			for (const Statement* stmt : seq)
			{
				if (auto subseq = dyn_cast<SequenceStatement>(stmt))
				{
					appendSequence(into, *subseq);
				}
				else if (auto cloned = visit(*stmt))
				{
					into.push_back(cloned);
				}
			}
		}
		
		Statement* cloneBody(const Statement* oldBody)
		{
			if (oldBody == nullptr)
			{
				return nullptr;
			}
			else if (auto seq = dyn_cast<SequenceStatement>(oldBody))
			{
				deque<NOT_NULL(Statement)> result;
				appendSequence(result, *seq);
				auto newSequence = ctx.sequence();
				for (NOT_NULL(Statement) stmt : result)
				{
					newSequence->pushBack(stmt);
				}
				return newSequence;
			}
			else
			{
				return visit(*oldBody);
			}
		}
		
	public:
		StatementCloneVisitor(AstContext& ctx)
		: ctx(ctx), expressionCloner(ctx)
		{
		}
		
		Statement* visitNoop(const NoopStatement& noop)
		{
			return nullptr;
		}
		
		Statement* visitSequence(const SequenceStatement& sequence)
		{
			return cloneBody(&sequence);
		}
		
		Statement* visitIfElse(const IfElseStatement& ifElse)
		{
			auto condition = expressionCloner.visit(*ifElse.getCondition());
			auto ifBody = cloneBody(ifElse.getIfBody());
			return ctx.ifElse(condition, ifBody == nullptr ? ctx.noop() : ifBody, cloneBody(ifElse.getElseBody()));
		}
		
		Statement* visitLoop(const LoopStatement& loop)
		{
			auto condition = expressionCloner.visit(*loop.getCondition());
			auto loopBody = cloneBody(loop.getLoopBody());
			return ctx.loop(condition, loop.getPosition(), loopBody == nullptr ? ctx.noop() : loopBody);
		}
		
		Statement* visitKeyword(const KeywordStatement& keyword)
		{
			Expression* cloned = nullptr;
			if (auto expression = keyword.getOperand())
			{
				cloned = expressionCloner.visit(*expression);
			}
			return ctx.keyword(&*keyword.name, cloned);
		}
		
		Statement* visitExpr(const ExpressionStatement& expression)
		{
			return ctx.expr(expressionCloner.visit(*expression.getExpression()));
		}
		
		Statement* visitDefault(const ExpressionUser& user)
		{
			llvm_unreachable("unimplemented expression clone case");
		}
	};
}

NOT_NULL(Expression) CloneVisitor::clone(AstContext& context, const Expression& toClone)
{
	return ExpressionCloneVisitor(context).visit(toClone);
}

NOT_NULL(Statement) CloneVisitor::clone(AstContext& context, const Statement& toClone)
{
	return StatementCloneVisitor(context).visit(toClone);
}

NOT_NULL(ExpressionUser) CloneVisitor::clone(AstContext& context, const ExpressionUser& toClone)
{
	if (auto expr = dyn_cast<Expression>(&toClone))
	{
		return &*clone(context, *expr);
	}
	else
	{
		return &*clone(context, cast<Statement>(toClone));
	}
}
