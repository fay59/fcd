//
// pass_branchcombine.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "ast_passes.h"
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
	
	class ConsecutiveCombiner : public AstVisitor<ConsecutiveCombiner, false, StatementReference>
	{
		AstContext& ctx;
		
	public:
		ConsecutiveCombiner(AstContext& ctx)
		: ctx(ctx)
		{
		}
		
		StatementReference optimizeSequence(StatementList&& list)
		{
			StatementReference newSequence;
			if (list.empty())
			{
				return newSequence;
			}
			
			IfElseStatement* lastIfElse = nullptr;
			while (!list.empty())
			{
				Statement* stmt = list.pop_front();
				IfElseStatement* thisIfElse = dyn_cast<IfElseStatement>(stmt);
				if (thisIfElse != nullptr)
				{
					if (lastIfElse != nullptr)
					{
						if (isLogicallySame(*thisIfElse->getCondition(), *lastIfElse->getCondition()))
						{
							StatementReference result;
							result->push_back(move(lastIfElse->getIfBody()));
							result->push_back(move(thisIfElse->getIfBody()));
							lastIfElse->getIfBody() = optimizeSequence(move(result).take()).take();
							
							result->push_back(move(lastIfElse->getElseBody()));
							result->push_back(move(thisIfElse->getElseBody()));
							lastIfElse->getElseBody() = optimizeSequence(move(result).take()).take();
							
							thisIfElse->dropAllReferences();
							continue;
						}
						else if (isLogicallyOpposite(*thisIfElse->getCondition(), *lastIfElse->getCondition()))
						{
							StatementReference result;
							result->push_back(move(lastIfElse->getIfBody()));
							result->push_back(move(thisIfElse->getElseBody()));
							lastIfElse->getIfBody() = optimizeSequence(move(result).take()).take();
							
							result->push_back(move(lastIfElse->getElseBody()));
							result->push_back(move(thisIfElse->getIfBody()));
							lastIfElse->getElseBody() = optimizeSequence(move(result).take()).take();
							
							thisIfElse->dropAllReferences();
							continue;
						}
					}
				}
				lastIfElse = thisIfElse;
				newSequence->push_back(stmt);
			}
			return visitAll(*this, move(newSequence).take());
		}
		
		StatementReference visitIfElse(IfElseStatement& ifElse)
		{
			StatementList::erase(&ifElse);
			ExpressionReference condition = &*ifElse.getCondition();
			auto ifBody = optimizeSequence(move(ifElse.getIfBody()));
			auto elseBody = optimizeSequence(move(ifElse.getElseBody()));
			ifElse.dropAllReferences();
			
			if (ifBody->empty() && elseBody->empty())
			{
				return {};
			}
			
			if (ifBody->empty())
			{
				condition = ctx.negate(condition.get());
				swap(ifBody, elseBody);
			}
			
			if (condition.get() == ctx.expressionForTrue())
			{
				return ifBody;
			}
			else if (condition.get() == ctx.expressionForFalse())
			{
				return elseBody;
			}
			
			// If there's an if and an else, always show the positive form first. For instance, "if foo != 4 A; else B;"
			// becomes "if foo == 4 B; else A;".
			if (!ifBody->empty() && !elseBody->empty())
			{
				auto negation = countNegationDepth(*condition.get());
				if (negation.second)
				{
					condition = const_cast<Expression*>(negation.first);
					swap(ifBody, elseBody);
				}
			}
			
			ifElse.setCondition(condition.get());
			ifElse.getIfBody() = move(ifBody).take();
			ifElse.getElseBody() = move(elseBody).take();
			return { &ifElse };
		}
		
		StatementReference visitLoop(LoopStatement& loop)
		{
			StatementList::erase(&loop);
			loop.getLoopBody() = optimizeSequence(move(loop.getLoopBody())).take();
			
			// Change `do { if (foo) { ... } } while (foo);` into `while (foo) { ... }`.
			if (loop.getPosition() == LoopStatement::PostTested)
			if (auto ifElse = dyn_cast_or_null<IfElseStatement>(loop.getLoopBody().single()))
			if (ifElse->getElseBody().empty())
			if (*ifElse->getCondition() == *loop.getCondition())
			{
				loop.getLoopBody() = move(ifElse->getIfBody());
				loop.setPosition(LoopStatement::PreTested);
				ifElse->dropAllReferences();
			}
			
			return { &loop };
		}
		
		StatementReference visitKeyword(KeywordStatement& keyword)
		{
			StatementList::erase(&keyword);
			return { &keyword };
		}
		
		StatementReference visitExpr(ExpressionStatement& expression)
		{
			StatementList::erase(&expression);
			return { &expression };
		}
		
		StatementReference visitDefault(ExpressionUser& user)
		{
			llvm_unreachable("unimplemented consecutive combiner case");
		}
	};
}

const char* AstConsecutiveCombiner::getName() const
{
	return "Combine Consecutive Statements";
}

void AstConsecutiveCombiner::doRun(FunctionNode& fn)
{
	fn.getBody() = ConsecutiveCombiner(fn.getContext()).optimizeSequence(move(fn.getBody())).take();
}
