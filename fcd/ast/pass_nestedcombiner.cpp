//
// pass_congruence.cpp
// Copyright (C) 2017 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "analysis_liveness.h"
#include "ast_passes.h"
#include "visitor.h"

using namespace llvm;
using namespace std;

namespace
{
	class MemoryOperationVisitor : public AstVisitor<MemoryOperationVisitor, false, void>
	{
		SmallVector<Expression*, 2> memoryOperations;
		
	public:
		const SmallVectorImpl<Expression*>& getMemoryOperations()
		{
			return memoryOperations;
		}
		
		void visitUnaryOperator(UnaryOperatorExpression& unary)
		{
			if (unary.getType() == UnaryOperatorExpression::Dereference)
			{
				memoryOperations.push_back(&unary);
			}
			visit(*unary.getOperand());
		}
		
		void visitNAryOperator(NAryOperatorExpression& nary)
		{
			if (nary.getType() == NAryOperatorExpression::Assign)
			{
				memoryOperations.push_back(&nary);
			}
			for (Expression* operand : nary.operands())
			{
				visit(*operand);
			}
		}
		
		void visitTernary(TernaryExpression& ternary)
		{
			visit(*ternary.getCondition());
			visit(*ternary.getTrueValue());
			visit(*ternary.getFalseValue());
		}
		
		void visitCast(CastExpression& cast)
		{
			return visit(*cast.getCastValue());
		}
		
		void visitSubscript(SubscriptExpression& subscript)
		{
			memoryOperations.push_back(&subscript);
			visit(*subscript.getPointer());
			visit(*subscript.getIndex());
		}
		
		void visitMemberAccess(MemberAccessExpression& memberAccess)
		{
			if (memberAccess.getAccessType() == MemberAccessExpression::PointerAccess)
			{
				memoryOperations.push_back(&memberAccess);
			}
			visit(*memberAccess.getBaseExpression());
		}
		
		void visitCall(CallExpression& call)
		{
			memoryOperations.push_back(&call);
			for (Expression* operand : call.operands())
			{
				visit(*operand);
			}
		}
		
		void visitAggregate(AggregateExpression& agg)
		{
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
			if (assignable.addressable)
			{
				memoryOperations.push_back(&assignable);
			}
		}
		
		void visitDefault(ExpressionUser& user)
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
		
		// XXX: LivenessAnalysis should probably be moved out to some global analysis tracking component so that it
		// doesn't have to be recalculated all the time.
		LivenessAnalysis liveness;
		
		StatementReference structurizeLoop(LoopStatement& loop)
		{
			// The LoopToSeq rule is never relevant with fcd's input. The DoWhile, NestedDoWhile, CondToSeq and
			// CondToSeqNeg are all very similar: you see if the last conditional of a loop has a break statement in it,
			// essentially.
			
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
		NestedCombiner(FunctionNode& fn)
		: ctx(fn.getContext())
		{
			liveness.collectStatementIndices(fn);
		}
		
		StatementReference visitIfElse(IfElseStatement& ifElse)
		{
			StatementList::erase(&ifElse);
			
			ifElse.getIfBody() = visitAll(*this, move(ifElse.getIfBody())).take();
			ifElse.getElseBody() = visitAll(*this, move(ifElse.getElseBody())).take();
			
			if (ifElse.getElseBody().empty())
			{
				// Check if there is no else, and the if body contained only an if statement. If so,
				// merge the two if statements.
				if (auto innerIfElse = dyn_cast_or_null<IfElseStatement>(ifElse.getIfBody().single()))
				if (innerIfElse->getElseBody().empty())
				{
					// However, be mindful of conditions that contain a memory operation with multiple uses. This is
					// because definition materialization could push the operation to appear to happen unconditionally,
					// which would be deeply incorrect.
					// (We only need to check that this is not the first use of the memory operation if there are more
					// than one uses.)
					ExpressionReference right = &*innerIfElse->getCondition();
					MemoryOperationVisitor memoryOperationsFinder;
					memoryOperationsFinder.visit(*right.get());
					
					bool mergeInnerIf = true;
					size_t innerIfElseConditionIndex = liveness.getIndex(innerIfElse).first;
					for (Expression* memoryOperation : memoryOperationsFinder.getMemoryOperations())
					{
						mergeInnerIf = any_of(LivenessAnalysis::getStatements(*memoryOperation), [&](Statement* stmt)
						{
							return liveness.getIndex(stmt).first < innerIfElseConditionIndex;
						});
						if (!mergeInnerIf)
						{
							break;
						}
					}
					
					if (mergeInnerIf)
					{
						ExpressionReference left = &*ifElse.getCondition();
						ifElse.setCondition(ctx.nary(NAryOperatorExpression::ShortCircuitAnd, left.get(), right.get()));
						ifElse.getIfBody() = move(innerIfElse->getIfBody());
						innerIfElse->dropAllReferences();
					}
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
	NestedCombiner nested(fn);
	fn.getBody() = visitAll(nested, move(fn.getBody())).take();
}
