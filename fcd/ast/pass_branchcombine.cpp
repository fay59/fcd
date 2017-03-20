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
			llvm_unreachable("unimplemented expression clone case");
		}
	};
	
#pragma mark - NestedCombiner and helpers
	bool isBreak(StatementList& list)
	{
		if (auto keyword = dyn_cast_or_null<KeywordStatement>(list.single()))
		{
			return strcmp(keyword->name, "break") == 0;
		}
		return false;
	}
	
	class NestedCombiner : public AstVisitor<NestedCombiner, false, StatementReference>
	{
		AstContext& ctx;
		
		// The LoopToSeq rule is never relevant with fcd's input. The DoWhile, NestedDoWhile, CondToSeq and
		// CondToSeqNeg are all very similar: you see if the last conditional of a loop has a break statement in it,
		// essentially.
		StatementReference structurizeLoop(LoopStatement& loop)
		{
			StatementList& body = loop.getLoopBody();
			SmallVector<pair<IfElseStatement*, LoopStatement::ConditionPosition>, 2> eligibleConditions;
			
			if (body.multiple())
			{
				if (auto frontCondition = dyn_cast<IfElseStatement>(body.front()))
				{
					eligibleConditions.emplace_back(frontCondition, LoopStatement::PreTested);
				}
				else if (auto backCondition = dyn_cast<IfElseStatement>(body.back()))
				{
					eligibleConditions.emplace_back(backCondition, LoopStatement::PostTested);
				}
			}
			else if (auto ifElse = dyn_cast_or_null<IfElseStatement>(body.single()))
			{
				eligibleConditions.emplace_back(ifElse, LoopStatement::PreTested);
			}
			
			for (auto& eligibleCondition : eligibleConditions)
			{
				auto ifElse = eligibleCondition.first;
				StatementList& trueBranch = ifElse->getIfBody();
				StatementList& falseBranch = ifElse->getElseBody();
				bool trueBreak = isBreak(trueBranch);
				bool falseBreak = isBreak(falseBranch);
				if (trueBreak != falseBreak)
				{
					ExpressionReference condition = &*ifElse->getCondition();
					StatementReference ifElseReplacement;
					if (trueBreak)
					{
						ifElseReplacement = move(falseBranch);
						condition = ctx.negate(condition.get());
					}
					else
					{
						ifElseReplacement = move(trueBranch);
					}
					
					if (eligibleCondition.second == LoopStatement::PreTested)
					{
						// Disown statements owned by the if since we're moving them around the AST.
						StatementList::insert(ifElse, move(ifElseReplacement).take());
						StatementList::erase(ifElse);
						ifElse->dropAllReferences();
					}
					else
					{
						// The conditional needs to stay in place.
						ifElse->setCondition(condition.get());
						ifElse->getIfBody() = move(ifElseReplacement).take();
						ifElse->getElseBody().clear();
					}
					
					loop.setCondition(ctx.nary(NAryOperatorExpression::ShortCircuitAnd, loop.getCondition(), condition.get()));
					loop.setPosition(eligibleCondition.second);
					break;
				}
			}
			return { &loop };
		}
		
	public:
		NestedCombiner(AstContext& ctx)
		: ctx(ctx)
		{
		}
		
		StatementReference visitIfElse(IfElseStatement& ifElse)
		{
			StatementList::erase(&ifElse);
			
			ifElse.getIfBody() = visitAll(*this, move(ifElse.getIfBody())).take();
			ifElse.getElseBody() = visitAll(*this, move(ifElse.getElseBody())).take();
			
			// Check if there is no else, and the if body contained only an if statement. If so,
			// merge the two if statements.
			if (ifElse.getElseBody().empty())
			if (auto innerIfElse = dyn_cast_or_null<IfElseStatement>(ifElse.getIfBody().single()))
			if (innerIfElse->getElseBody().empty())
			{
				auto left = ifElse.getCondition();
				auto right = innerIfElse->getCondition();
				ifElse.setCondition(ctx.nary(NAryOperatorExpression::ShortCircuitAnd, left, right));
				ifElse.getIfBody() = move(innerIfElse->getIfBody());
				innerIfElse->dropAllReferences();
			}
			
			return { &ifElse };
		}
		
		StatementReference visitLoop(LoopStatement& loop)
		{
			StatementList::erase(&loop);
			loop.getLoopBody() = visitAll(*this, move(loop.getLoopBody())).take();
			return structurizeLoop(loop);
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
	ConsecutiveCombiner consecutive(context);
	NestedCombiner nested(context);
	fn.getBody() = consecutive.optimizeSequence(move(fn.getBody())).take();
	fn.getBody() = visitAll(nested, move(fn.getBody())).take();
	// NestedCombiner leaves clutter that ConsecutiveCombiner could get rid of
	fn.getBody() = consecutive.optimizeSequence(move(fn.getBody())).take();
}
