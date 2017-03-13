//
// pass_simplifyconditions.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "ast_passes.h"
#include "visitor.h"

#include <unordered_set>

using namespace llvm;
using namespace std;

namespace
{
	inline UnaryOperatorExpression* match(Expression* expr, UnaryOperatorExpression::UnaryOperatorType type)
	{
		if (auto unary = dyn_cast_or_null<UnaryOperatorExpression>(expr))
		if (unary->getType() == type)
		{
			return unary;
		}
		
		return nullptr;
	}
	
	UnaryOperatorExpression* matchNegation(Expression* expr)
	{
		return match(expr, UnaryOperatorExpression::LogicalNegate);
	}
	
	pair<Expression*, bool> countNegationDepth(Expression& expr)
	{
		bool isNegated = false;
		Expression* canonical;
		for (canonical = &expr; auto negation = matchNegation(canonical); canonical = negation->getOperand())
		{
			isNegated = !isNegated;
		}
		return make_pair(canonical, isNegated);
	}
	
	class ExpressionSimplifierVisitor : public AstVisitor<ExpressionSimplifierVisitor, false>
	{
		AstContext& ctx;
		std::unordered_set<const ExpressionUser*> visitedExpressions;
		
		void collectExpressionTerms(NAryOperatorExpression& baseExpression, SmallVectorImpl<Expression*>& trueTerms, SmallVectorImpl<Expression*>& falseTerms)
		{
			for (ExpressionUse& use : baseExpression.operands())
			{
				auto expr = use.getUse();
				if (auto nary = dyn_cast<NAryOperatorExpression>(expr))
				{
					if (nary->getType() == baseExpression.getType())
					{
						collectExpressionTerms(*nary, trueTerms, falseTerms);
						continue;
					}
				}
				
				auto isNegated = countNegationDepth(*expr);
				auto& terms = isNegated.second ? falseTerms : trueTerms;
				if (find(terms.begin(), terms.end(), isNegated.first) == terms.end())
				{
					terms.push_back(isNegated.first);
				}
			}
		}
		
		Expression* removeIdenticalTerms(NAryOperatorExpression& nary)
		{
			if (nary.getType() != NAryOperatorExpression::ShortCircuitOr && nary.getType() != NAryOperatorExpression::ShortCircuitAnd)
			{
				return &nary;
			}
			
			// This is allowed on both && and ||, since (a && a) == a and (a || a) == a.
			SmallVector<Expression*, 16> trueTerms;
			SmallVector<Expression*, 16> falseTerms;
			collectExpressionTerms(nary, trueTerms, falseTerms);
			
			auto trueExpression = ctx.expressionForTrue();
			auto falseExpression = ctx.expressionForFalse();
			SmallVector<Expression*, 16> expressions;
			for (Expression* falseTerm : falseTerms)
			{
				if (find(trueTerms.begin(), trueTerms.end(), falseTerm) != trueTerms.end())
				{
					// this will either be a totaulogy or a contradiction depending on the logical operator
					auto trueValue = ctx.expressionForTrue();
					return nary.getType() == NAryOperatorExpression::ShortCircuitOr ? trueValue : ctx.negate(trueValue);
				}
				
				if (falseTerm == trueExpression)
				{
					if (nary.getType() == NAryOperatorExpression::ShortCircuitAnd)
					{
						return falseExpression;
					}
				}
				else if (falseTerm == falseExpression)
				{
					if (nary.getType() == NAryOperatorExpression::ShortCircuitOr)
					{
						return trueExpression;
					}
				}
				else
				{
					expressions.push_back(ctx.negate(falseTerm));
				}
			}
			
			for (Expression* trueTerm : trueTerms)
			{
				if (trueTerm == trueExpression)
				{
					if (nary.getType() == NAryOperatorExpression::ShortCircuitOr)
					{
						return trueExpression;
					}
				}
				else if (trueTerm == falseExpression)
				{
					if (nary.getType() == NAryOperatorExpression::ShortCircuitAnd)
					{
						return falseExpression;
					}
				}
				else
				{
					expressions.push_back(trueTerm);
				}
			}
			
			unsigned i = 0;
			auto result = ctx.nary(nary.getType(), static_cast<unsigned>(expressions.size()));
			for (Expression* expression : expressions)
			{
				result->setOperand(i, expression);
				++i;
			}
			return result;
		}
		
	public:
		ExpressionSimplifierVisitor(AstContext& ctx)
		: ctx(ctx)
		{
		}
		
		void visitUnaryOperator(UnaryOperatorExpression& unary)
		{
			visit(*unary.getOperand());
			auto operand = unary.getOperand(); // might have changed
			
			if (unary.getType() == UnaryOperatorExpression::LogicalNegate)
			{
				if (auto innerNegate = match(operand, UnaryOperatorExpression::LogicalNegate))
				{
					unary.replaceAllUsesWith(innerNegate->getOperand());
					unary.dropAllReferences();
				}
				else if (auto innerNary = dyn_cast<NAryOperatorExpression>(operand))
				{
					auto op = innerNary->getType();
					if (innerNary->operands_size() == 2 && op >= NAryOperatorExpression::ComparisonMin && op <= NAryOperatorExpression::ComparisonMax)
					{
						auto flippedOp = static_cast<NAryOperatorExpression::NAryOperatorType>(op ^ 1);
						auto replacement = ctx.nary(flippedOp, innerNary->getOperand(0), innerNary->getOperand(1));
						unary.replaceAllUsesWith(replacement);
						unary.dropAllReferences();
					}
				}
			}
			else if (unary.getType() == UnaryOperatorExpression::Dereference)
			{
				if (auto innerAddressOf = match(operand, UnaryOperatorExpression::AddressOf))
				{
					unary.replaceAllUsesWith(innerAddressOf->getOperand());
					unary.dropAllReferences();
				}
			}
		}
		
		void visitNAryOperator(NAryOperatorExpression& nary)
		{
			ExpressionReference naryRef = &nary;
			
			// Negation distribution kills term collection, so do that first before visiting child nodes
			Expression* result = removeIdenticalTerms(nary);
			for (ExpressionUse& use : result->operands())
			{
				visit(*use.getUse());
			}
			
			if (result != &nary)
			{
				nary.replaceAllUsesWith(result);
				nary.dropAllReferences();
			}
		}
		
		void visitMemberAccess(MemberAccessExpression& memberAccess)
		{
			visit(*memberAccess.getBaseExpression());
		}
		
		void visitTernary(TernaryExpression& ternary)
		{
			visit(*ternary.getCondition());
			visit(*ternary.getTrueValue());
			visit(*ternary.getFalseValue());
		}
		
		void visitCall(CallExpression& call)
		{
			visit(*call.getCallee());
			for (ExpressionUse& use : call.params())
			{
				visit(*use.getUse());
			}
		}
		
		void visitCast(CastExpression& cast)
		{
			visit(*cast.getCastValue());
		}
		
		void visitAggregate(AggregateExpression& agg)
		{
			for (ExpressionUse& use : agg.operands())
			{
				visit(*use.getUse());
			}
		}
		
		void visitSubscript(SubscriptExpression& subscript)
		{
			visit(*subscript.getPointer());
			visit(*subscript.getIndex());
			
			if (auto addressOf = match(subscript.getPointer(), UnaryOperatorExpression::AddressOf))
			if (auto constantIndex = dyn_cast<NumericExpression>(subscript.getIndex()))
			if (constantIndex->ui64 == 0)
			{
				subscript.replaceAllUsesWith(addressOf->getOperand());
				subscript.dropAllReferences();
			}
		}
		
		void visitNumeric(NumericExpression& numeric)
		{
		}
		
		void visitToken(TokenExpression& token)
		{
		}
		
		void visitAssembly(AssemblyExpression& assembly)
		{
		}
		
		void visitAssignable(AssignableExpression& assignable)
		{
		}
		
		void visit(ExpressionUser& user)
		{
			auto result = visitedExpressions.insert(&user);
			if (result.second)
			{
				AstVisitor<ExpressionSimplifierVisitor, false>::visit(user);
			}
		}
		
		void visitDefault(ExpressionUser& user)
		{
			llvm_unreachable("unimplemented expression simplification case");
		}
	};
	
	class StatementSimplifierVisitor : public AstVisitor<StatementSimplifierVisitor, false>
	{
		ExpressionSimplifierVisitor exprVisitor;
		
	public:
		StatementSimplifierVisitor(AstContext& ctx)
		: exprVisitor(ctx)
		{
		}
		
		void visitIfElse(IfElseStatement& ifElse)
		{
			exprVisitor.visit(*ifElse.getCondition());
			for (Statement* stmt : ifElse.getIfBody())
			{
				visit(*stmt);
			}
			for (Statement* stmt : ifElse.getElseBody())
			{
				visit(*stmt);
			}
		}
		
		void visitLoop(LoopStatement& loop)
		{
			exprVisitor.visit(*loop.getCondition());
			for (Statement* stmt : loop.getLoopBody())
			{
				visit(*stmt);
			}
		}
		
		void visitKeyword(KeywordStatement& keyword)
		{
			if (auto operand = keyword.getOperand())
			{
				exprVisitor.visit(*operand);
			}
		}
		
		void visitExpr(ExpressionStatement& expression)
		{
			if (auto expr = expression.getExpression())
			{
				exprVisitor.visit(*expr);
			}
		}
		
		void visitDefault(ExpressionUser& user)
		{
			llvm_unreachable("unimplemented expression simplification case");
		}
	};
}

void AstSimplifyExpressions::doRun(FunctionNode &fn)
{
	StatementSimplifierVisitor visitor(fn.getContext());
	visitAll(visitor, fn.getBody());
}

const char* AstSimplifyExpressions::getName() const
{
	return "Simplify conditions";
}
