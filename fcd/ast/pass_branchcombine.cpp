//
// pass_branchcombine.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "clone.h"
#include "ast_passes.h"
#include "visitor.h"

#include <cstring>
#include <deque>

using namespace llvm;
using namespace std;

namespace
{
#pragma mark - ConsecutiveCombiner and helpers
	bool isLogicallySame(const Expression& a, const Expression& b)
	{
		return a == b;
	}
	
	const UnaryOperatorExpression* matchNegation(const Expression* expr)
	{
		if (auto unary = dyn_cast<UnaryOperatorExpression>(expr))
		if (unary->getType() == UnaryOperatorExpression::LogicalNegate)
		{
			return unary;
		}
		return nullptr;
	}
	
	pair<const Expression*, bool> countNegationDepth(const Expression& expr)
	{
		bool isNegated = false;
		const Expression* canonical;
		for (canonical = &expr; auto negation = matchNegation(canonical); canonical = negation->getOperand())
		{
			isNegated = !isNegated;
		}
		return make_pair(canonical, isNegated);
	}
	
	bool isLogicallyOpposite(const Expression& a, const Expression& b)
	{
		auto aInfo = countNegationDepth(a);
		auto bInfo = countNegationDepth(b);
		return aInfo.second != bInfo.second && *aInfo.first == *bInfo.first;
	}
	
	class ConsecutiveCombiner : public AstVisitor<ConsecutiveCombiner, false, Statement*>
	{
		AstContext& ctx;
		
		void collectStatements(deque<NOT_NULL(Statement)>& into, Statement* stmt)
		{
			if (stmt == nullptr)
			{
				return;
			}
			
			if (auto seq = dyn_cast<SequenceStatement>(stmt))
			{
				for (Statement* substatement : *seq)
				{
					if (auto subseq = dyn_cast<SequenceStatement>(substatement))
					{
						collectStatements(into, subseq);
					}
					else if (auto simplified = visit(*substatement))
					{
						into.push_back(simplified);
					}
				}
			}
			else if (auto simplified = visit(*stmt))
			{
				into.push_back(simplified);
			}
		}
		
		Statement* optimizeSequence(deque<NOT_NULL(Statement)>& list)
		{
			if (list.size() == 0)
			{
				return nullptr;
			}
			else if (list.size() == 1)
			{
				return list.front();
			}
			
			auto newSequence = ctx.sequence();
			IfElseStatement* lastIfElse = nullptr;
			for (NOT_NULL(Statement) stmt : list)
			{
				if (IfElseStatement* thisIfElse = dyn_cast<IfElseStatement>(stmt))
				{
					if (lastIfElse != nullptr)
					{
						if (isLogicallySame(*thisIfElse->getCondition(), *lastIfElse->getCondition()))
						{
							deque<NOT_NULL(Statement)> result;
							collectStatements(result, lastIfElse->getIfBody());
							collectStatements(result, thisIfElse->getIfBody());
							if (auto old = lastIfElse->setIfBody(optimizeSequence(result)))
							{
								old->dropAllReferences();
							}
							
							result.clear();
							collectStatements(result, lastIfElse->getElseBody());
							collectStatements(result, thisIfElse->getElseBody());
							if (auto old = lastIfElse->setElseBody(optimizeSequence(result)))
							{
								old->dropAllReferences();
							}
							
							thisIfElse->dropAllReferences();
							continue;
						}
						else if (isLogicallyOpposite(*thisIfElse->getCondition(), *lastIfElse->getCondition()))
						{
							deque<NOT_NULL(Statement)> result;
							collectStatements(result, lastIfElse->getIfBody());
							collectStatements(result, thisIfElse->getElseBody());
							if (auto old = lastIfElse->setIfBody(optimizeSequence(result)))
							{
								old->dropAllReferences();
							}
							
							result.clear();
							collectStatements(result, lastIfElse->getElseBody());
							collectStatements(result, thisIfElse->getIfBody());
							if (auto old = lastIfElse->setElseBody(optimizeSequence(result)))
							{
								old->dropAllReferences();
							}
							
							thisIfElse->dropAllReferences();
							continue;
						}
					}
					lastIfElse = thisIfElse;
				}
				newSequence->pushBack(stmt);
			}
			return newSequence;
		}
		
		Statement* flattenBody(Statement* oldBody)
		{
			if (oldBody == nullptr)
			{
				return nullptr;
			}
			
			deque<NOT_NULL(Statement)> result;
			collectStatements(result, oldBody);
			return optimizeSequence(result);
		}
		
	public:
		ConsecutiveCombiner(AstContext& ctx)
		: ctx(ctx)
		{
		}
		
		Statement* visitNoop(NoopStatement& noop)
		{
			return nullptr;
		}
		
		Statement* visitSequence(SequenceStatement& sequence)
		{
			return flattenBody(&sequence);
		}
		
		Statement* visitIfElse(IfElseStatement& ifElse)
		{
			auto ifBody = flattenBody(ifElse.getIfBody());
			auto elseBody = flattenBody(ifElse.getElseBody());
			
			if (ifBody == nullptr && elseBody == nullptr)
			{
				ifElse.dropAllReferences();
				return nullptr;
			}
			
			ExpressionReference condition = &*ifElse.getCondition();
			if (ifBody == nullptr)
			{
				condition = ctx.negate(condition.get());
				swap(ifBody, elseBody);
			}
			
			if (condition.get() == ctx.expressionForTrue())
			{
				ifElse.setIfBody(ctx.noop());
				ifElse.dropAllReferences();
				return ifBody;
			}
			else if (condition.get() == ctx.expressionForFalse())
			{
				ifElse.setElseBody(nullptr);
				ifElse.dropAllReferences();
				return elseBody;
			}
			
			// If there's an if and an else, always show the positive form first. For instance, "if foo != 4 A; else B;"
			// becomes "if foo == 4 B; else A;".
			if (ifBody != nullptr && elseBody != nullptr)
			{
				auto negation = countNegationDepth(*condition.get());
				if (negation.second)
				{
					condition = const_cast<Expression*>(negation.first);
					swap(ifBody, elseBody);
				}
			}
			
			return ctx.ifElse(condition.get(), ifBody, elseBody);
		}
		
		Statement* visitLoop(LoopStatement& loop)
		{
			auto loopBody = flattenBody(loop.getLoopBody());
			return ctx.loop(loop.getCondition(), loop.getPosition(), loopBody == nullptr ? ctx.noop() : loopBody);
		}
		
		Statement* visitKeyword(KeywordStatement& keyword)
		{
			return ctx.keyword(&*keyword.name, keyword.getOperand());
		}
		
		Statement* visitExpr(ExpressionStatement& expression)
		{
			return ctx.expr(expression.getExpression());
		}
		
		Statement* visitDefault(ExpressionUser& user)
		{
			llvm_unreachable("unimplemented expression clone case");
		}
	};
	
#pragma mark - NestedCombiner and helpers
	class FindBreak : public AstVisitor<FindBreak, false, Statement*>
	{
	public:
		Statement* visitNoop(NoopStatement& noop)
		{
			return nullptr;
		}
		
		Statement* visitSequence(SequenceStatement& sequence)
		{
			// unconditional breaks will necessarily be in the last statement
			return sequence.size() > 0 ? visit(*sequence.back()) : nullptr;
		}
		
		Statement* visitIfElse(IfElseStatement& ifElse)
		{
			return nullptr;
		}
		
		Statement* visitLoop(LoopStatement& loop)
		{
			// a break found inside a loop won't have any impact on the outer loop, so leave it out
			return nullptr;
		}
		
		Statement* visitKeyword(KeywordStatement& keyword)
		{
			return strcmp(keyword.name, "break") == 0 ? &keyword : nullptr;
		}
		
		Statement* visitExpr(ExpressionStatement& expression)
		{
			return nullptr;
		}
		
		Statement* visitDefault(ExpressionUser& user)
		{
			llvm_unreachable("unimplemented expression clone case");
		}
	};
	
	Statement* findBreak(Statement* from)
	{
		return from == nullptr ? nullptr : FindBreak().visit(*from);
	}
	
	Statement* get(Statement* stmt, Statement* (SequenceStatement::*method)())
	{
		while (auto seq = dyn_cast<SequenceStatement>(stmt))
		{
			if (seq->size() == 0)
			{
				break;
			}
			stmt = (seq->*method)();
		}
		return stmt;
	}
	
	class NestedCombiner : public AstVisitor<NestedCombiner, false, Statement*>
	{
		AstContext& ctx;
		
		// CondToSeq, CondToSeqNeg, While and DoWhile all generalized in one single rule:
		// If the loop starts or ends with a condition that breaks, then the loop has to be refined.
		// (Also, these are allowed to run on loops that aren't endless. Improvement!)
		// This doesn't do NestedDoWhile or LoopToSeq. LoopToSeq isn't expected to ever occur in fcd;
		// NestedDoWhile hasn't been reimplemented.
		Statement* structurizeLoop(LoopStatement& loop)
		{
			Statement* body = loop.getLoopBody();
			SmallVector<pair<IfElseStatement*, LoopStatement::ConditionPosition>, 2> eligibleConditions;
			if (auto statement = dyn_cast<IfElseStatement>(body))
			{
				eligibleConditions.emplace_back(statement, LoopStatement::PreTested);
			}
			else if (auto seq = dyn_cast<SequenceStatement>(body))
			{
				if (seq->size() > 0)
				{
					if (auto frontCondition = dyn_cast<IfElseStatement>(get(seq, &SequenceStatement::front)))
					{
						eligibleConditions.emplace_back(frontCondition, LoopStatement::PreTested);
					}
					else if (auto backCondition = dyn_cast<IfElseStatement>(get(seq, &SequenceStatement::back)))
					{
						eligibleConditions.emplace_back(backCondition, LoopStatement::PostTested);
					}
				}
			}
			
			for (auto& eligibleCondition : eligibleConditions)
			{
				auto ifElse = eligibleCondition.first;
				auto trueBranch = ifElse->getIfBody();
				auto falseBranch = ifElse->getElseBody();
				ExpressionReference ifElseCond = &*ifElse->getCondition();
				Statement* trueBreak = findBreak(trueBranch);
				Statement* falseBreak = findBreak(falseBranch);
				if ((trueBreak == nullptr) != (falseBreak == nullptr))
				{
					Statement* breakStatement;
					Statement* loopSuccessor;
					Statement* ifElseReplacement;
					ExpressionReference condition;
					if (trueBreak != nullptr)
					{
						breakStatement = trueBreak;
						loopSuccessor = trueBranch;
						// It's possible that there's no else statement.
						ifElseReplacement = falseBranch == nullptr ? ctx.noop() : falseBranch;
						condition = ctx.negate(ifElseCond.get());
					}
					else
					{
						breakStatement = falseBreak;
						// There has to be an else statement, since it contained a break.
						loopSuccessor = falseBranch;
						ifElseReplacement = trueBranch;
						condition = ifElseCond;
					}
					
					ifElse->setElseBody(nullptr);
					if (eligibleCondition.second == LoopStatement::PreTested)
					{
						// Disown statements owned by the if since we're moving them around the AST.
						ifElse->setIfBody(ctx.noop());
						ifElse->dropAllReferences();
						ifElse->getParent()->replaceChild(ifElse, ifElseReplacement);
					}
					else
					{
						// The condition needs to stay.
						ifElse->setIfBody(ifElseReplacement);
						ifElse->setCondition(condition.get());
					}
					
					auto newLoopBody = loop.getLoopBody();
					loop.setLoopBody(ctx.noop());
					
					auto newCondition = ctx.nary(NAryOperatorExpression::ShortCircuitAnd, loop.getCondition(), condition.get());
					auto newLoop = ctx.loop(newCondition, eligibleCondition.second, newLoopBody);
					
					auto outerBody = ctx.sequence();
					outerBody->pushBack(structurizeLoop(*newLoop));
					outerBody->pushBack(loopSuccessor);
					breakStatement->getParent()->replaceChild(breakStatement, ctx.noop());
					return outerBody;
				}
			}
			return &loop;
		}
		
	public:
		NestedCombiner(AstContext& ctx)
		: ctx(ctx)
		{
		}
		
		Statement* visitNoop(NoopStatement& noop)
		{
			return &noop;
		}
		
		Statement* visitSequence(SequenceStatement& sequence)
		{
			for (auto iter = sequence.begin(); iter != sequence.end(); ++iter)
			{
				sequence.replace(iter, visit(**iter));
			}
			return &sequence;
		}
		
		Statement* visitIfElse(IfElseStatement& ifElse)
		{
			auto ifBody = visit(*ifElse.getIfBody());
			ifElse.setIfBody(ifBody);
			if (auto elseBody = ifElse.getElseBody())
			{
				ifElse.setElseBody(visit(*elseBody));
			}
			else if (auto innerIf = dyn_cast<IfElseStatement>(ifBody))
			{
				if (innerIf->getElseBody() == nullptr)
				{
					auto innerBody = innerIf->getIfBody();
					innerIf->setIfBody(ctx.noop());
					
					auto left = ifElse.getCondition();
					auto right = innerIf->getCondition();
					auto combined = ctx.nary(NAryOperatorExpression::ShortCircuitAnd, left, right);
					
					ifElse.setCondition(combined);
					ifElse.setIfBody(innerBody);
				}
			}
			
			return &ifElse;
		}
		
		Statement* visitLoop(LoopStatement& loop)
		{
			loop.setLoopBody(visit(*loop.getLoopBody()));
			return structurizeLoop(loop);
		}
		
		Statement* visitKeyword(KeywordStatement& keyword)
		{
			return &keyword;
		}
		
		Statement* visitExpr(ExpressionStatement& expression)
		{
			return &expression;
		}
		
		Statement* visitDefault(ExpressionUser& user)
		{
			llvm_unreachable("unimplemented expression clone case");
		}
	};
}

const char* AstBranchCombine::getName() const
{
	return "Combine Branches";
}

void AstBranchCombine::doRun(FunctionNode& fn)
{
	auto& context = fn.getContext();
	Statement* body = fn.getBody();
	body = ConsecutiveCombiner(context).visit(*body);
	body = NestedCombiner(context).visit(*body);
	// NestedCombiner leaves clutter that ConsecutiveCombiner could get rid of
	body = ConsecutiveCombiner(context).visit(*body);
	fn.setBody(body);
}
