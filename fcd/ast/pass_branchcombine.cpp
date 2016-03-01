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
	bool isBreak(const Statement* statement)
	{
		if (auto kw = dyn_cast_or_null<KeywordStatement>(statement))
		{
			return strcmp(kw->name, "break") == 0;
		}
		return false;
	}
	
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
	
	class StatementCombineVisitor : public AstVisitor<StatementCombineVisitor, false, Statement*>
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
		
		bool optimizeLoop(LoopStatement& loop, Statement& testStatement)
		{
			if (auto firstIf = dyn_cast<IfElseStatement>(&testStatement))
			{
				auto ifBody = firstIf->getIfBody();
				auto elseBody = firstIf->getElseBody();
				if (isBreak(ifBody))
				{
					loop.setCondition(ctx.negate(firstIf->getCondition()));
					firstIf->discardCondition();
					
					deque<NOT_NULL(Statement)> statements;
					collectStatements(statements, elseBody);
					collectStatements(statements, loop.getLoopBody());
					loop.setLoopBody(optimizeSequence(statements));
					return true;
				}
				else if (isBreak(elseBody))
				{
					loop.setCondition(firstIf->getCondition());
					firstIf->discardCondition();
					
					deque<NOT_NULL(Statement)> statements;
					collectStatements(statements, ifBody);
					collectStatements(statements, loop.getLoopBody());
					loop.setLoopBody(optimizeSequence(statements));
					return true;
				}
			}
			return false;
		}
		
	public:
		StatementCombineVisitor(AstContext& ctx)
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
}

const char* AstBranchCombine::getName() const
{
	return "Combine Branches";
}

void AstBranchCombine::doRun(FunctionNode& fn)
{
	StatementCombineVisitor combinator(fn.getContext());
	fn.setBody(combinator.visit(*fn.getBody()));
}
