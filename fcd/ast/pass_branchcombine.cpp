//
// pass_branchcombine.cpp
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
#include "pass_branchcombine.h"
#include "visitor.h"

#include <cstring>
#include <deque>

using namespace llvm;
using namespace std;

namespace
{
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
							lastIfElse->setIfBody(optimizeSequence(result));
							
							result.clear();
							collectStatements(result, lastIfElse->getElseBody());
							collectStatements(result, thisIfElse->getElseBody());
							lastIfElse->setElseBody(optimizeSequence(result));
							
							thisIfElse->discardCondition();
							continue;
						}
						else if (isLogicallyOpposite(*thisIfElse->getCondition(), *lastIfElse->getCondition()))
						{
							deque<NOT_NULL(Statement)> result;
							collectStatements(result, lastIfElse->getIfBody());
							collectStatements(result, thisIfElse->getElseBody());
							lastIfElse->setIfBody(optimizeSequence(result));
							
							result.clear();
							collectStatements(result, lastIfElse->getElseBody());
							collectStatements(result, thisIfElse->getIfBody());
							lastIfElse->setElseBody(optimizeSequence(result));
							
							thisIfElse->discardCondition();
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
				return ctx.noop();
			}
			
			auto condition = ifElse.getCondition();
			if (ifBody == nullptr)
			{
				condition = ctx.negate(condition);
				swap(ifBody, elseBody);
			}
			
			return ctx.ifElse(condition, ifBody, elseBody);
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
	
	class NestedCombiner : public AstVisitor<NestedCombiner, false, Statement*>
	{
		AstContext& ctx;
		
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
			return &loop;
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
	Statement* body = fn.getBody();
	body = ConsecutiveCombiner(fn.getContext()).visit(*body);
	body = NestedCombiner(fn.getContext()).visit(*body);
	fn.setBody(body);
}
