//
// pass_congruence.cpp
// Copyright (C) 2017 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "ast_passes.h"
#include "visitor.h"

using namespace llvm;
using namespace std;

namespace
{
	
	class MemoryOperationVisitor : public AstVisitor<MemoryOperationVisitor, false, bool>
	{
	public:
		bool visitUnaryOperator(UnaryOperatorExpression& unary)
		{
			return unary.getType() == UnaryOperatorExpression::Dereference || visit(*unary.getOperand());
		}
		
		bool visitNAryOperator(NAryOperatorExpression& nary)
		{
			return nary.getType() == NAryOperatorExpression::Assign || any_of(nary.operands(), [&](ExpressionUse& use)
			{
				return visit(*use.getUse());
			});
		}
		
		bool visitTernary(TernaryExpression& ternary)
		{
			return visit(*ternary.getCondition()) || visit(*ternary.getTrueValue()) || visit(*ternary.getFalseValue());
		}
		
		bool visitCast(CastExpression& cast)
		{
			return visit(*cast.getCastValue());
		}
		
		bool visitSubscript(SubscriptExpression& subscript)
		{
			return true;
		}
		
		bool visitMemberAccess(MemberAccessExpression& memberAccess)
		{
			return true;
		}
		
		bool visitCall(CallExpression& call)
		{
			return true;
		}
		
		bool visitAggregate(AggregateExpression& agg)
		{
			return false;
		}
		
		bool visitNumeric(NumericExpression& numeric)
		{
			return false;
		}
		
		bool visitToken(TokenExpression& token)
		{
			return false;
		}
		
		bool visitAssembly(AssemblyExpression& assembly)
		{
			return false;
		}
		
		bool visitAssignable(AssignableExpression& assignable)
		{
			return false;
		}
		
		bool visitDefault(ExpressionUser& user)
		{
			llvm_unreachable("unimplemented expression clone case");
		}
	};
	
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
				// However, be mindful of conditions that contain a memory operation with multiple uses. This is because
				// definition materialization could push the operation to appear to happen unconditionally, which would
				// be deeply incorrect.
				// XXX: the right way to solve this problem is to use LivenessAnalysis (from the variable congruence
				// pass) to check for statement ordering, but the right way to do that is to expand the pass framework
				// to have persistent and updatable analyses. It doesn't feel (yet) like this change would pull its own
				// weight, so for now, just check that the condition doesn't involve memory operations.
				ExpressionReference right = &*innerIfElse->getCondition();
				if (!MemoryOperationVisitor().visit(*right.get()))
				{
					ExpressionReference left = &*ifElse.getCondition();
					ifElse.setCondition(ctx.nary(NAryOperatorExpression::ShortCircuitAnd, left.get(), right.get()));
					ifElse.getIfBody() = move(innerIfElse->getIfBody());
					innerIfElse->dropAllReferences();
				}
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
			llvm_unreachable("unimplemented nested combiner case");
		}
	};
}

const char* AstNestedCombiner::getName() const
{
	return "Combine Nested Statements";
}

void AstNestedCombiner::doRun(FunctionNode& fn)
{
	NestedCombiner nested(fn.getContext());
	fn.getBody() = visitAll(nested, move(fn.getBody())).take();
}
