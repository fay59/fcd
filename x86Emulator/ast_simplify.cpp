//
//  ast_simplify.cpp
//  x86Emulator
//
//  Created by Félix on 2015-07-18.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#include "ast_simplify.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/Casting.h>
SILENCE_LLVM_WARNINGS_END()

#include <algorithm>

using namespace llvm;
using namespace std;

namespace
{
	bool containsBreakStatement(Statement* statement)
	{
		if (statement == nullptr)
		{
			return false;
		}
		
		if (statement == KeywordNode::breakNode)
		{
			return true;
		}
		
		if (auto seq = dyn_cast<SequenceNode>(statement))
		{
			for (size_t i = 0; i < seq->statements.size(); i++)
			{
				if (containsBreakStatement(seq->statements[i]))
					return true;
			}
		}
		else if (auto ifElse = dyn_cast<IfElseNode>(statement))
		{
			return containsBreakStatement(ifElse->ifBody) || containsBreakStatement(ifElse->elseBody);
		}
		
		// Intentionally leaving out while statements, since a break in a while statement will not affect the outer
		// loop.
		return false;
	}
	
	void removeBranch(DumbAllocator& pool, SequenceNode& parent, size_t ifIndex, bool branch)
	{
		static constexpr Statement* IfElseNode::*branchSelector[] = { &IfElseNode::elseBody, &IfElseNode::ifBody };
		size_t selectorIndex = !!branch; // make sure that branch is either 0 or 1
		
		IfElseNode* ifElse = cast<IfElseNode>(parent.statements[ifIndex]);
		ifElse->*branchSelector[selectorIndex] = ifElse->*branchSelector[!selectorIndex];
		if (ifElse->*branchSelector[selectorIndex] != nullptr)
		{
			ifElse->*branchSelector[!selectorIndex] = nullptr;
			ifElse->condition = wrapWithNegate(pool, ifElse->condition);
		}
		else
		{
			parent.statements.erase_at(ifIndex);
		}
	}
	
	NAryOperatorExpression* changeOperator(DumbAllocator& pool, NAryOperatorExpression* expr, NAryOperatorExpression::NAryOperatorType op)
	{
		auto result = pool.allocate<NAryOperatorExpression>(pool, op);
		result->addOperands(expr->operands.begin(), expr->operands.end());
		return result;
	}
	
	Expression* simplifyNegation(DumbAllocator& pool, UnaryOperatorExpression* negated)
	{
		assert(negated->type == UnaryOperatorExpression::LogicalNegate);
		if (auto nary = dyn_cast<NAryOperatorExpression>(negated->operand))
		{
			
#define OP_INVERT(x, y) case NAryOperatorExpression::x: return changeOperator(pool, nary, NAryOperatorExpression::y);
#define OP_PAIR(x, y) OP_INVERT(x, y) OP_INVERT(y, x)
			switch (nary->type)
			{
				OP_PAIR(SmallerThan, GreaterOrEqualTo)
				OP_PAIR(SmallerOrEqualTo, GreaterThan)
				OP_PAIR(Equal, NotEqual)
				default: break;
			}
#undef OP_INVERT
#undef OP_PAIR
			
		}
		
		// no obvious simplification possible
		return negated;
	}
	
	inline Expression* simplifyCondition(DumbAllocator& pool, Expression* expr)
	{
		if (auto unary = dyn_cast<UnaryOperatorExpression>(expr))
		{
			if (unary->type == UnaryOperatorExpression::LogicalNegate)
			{
				return simplifyNegation(pool, unary);
			}
		}
		else if (auto nary = dyn_cast<NAryOperatorExpression>(expr))
		{
			for (auto& subExpression : nary->operands)
			{
				subExpression = simplifyCondition(pool, subExpression);
			}
		}
		return expr;
	}
	
	Statement* appendStatements(DumbAllocator& pool, Statement* a, Statement* b)
	{
		if (a == nullptr)
		{
			return b;
		}
		
		if (b == nullptr)
		{
			return a;
		}
		
		SequenceNode* seq = pool.allocate<SequenceNode>(pool);
		seq->statements.push_back(a);
		seq->statements.push_back(b);
		return seq;
	}
}

Statement* recursivelySimplifyIfElse(DumbAllocator& pool, IfElseNode* statement);

Expression* wrapWithNegate(DumbAllocator& pool, Expression* toNegate)
{
	if (auto unary = dyn_cast<UnaryOperatorExpression>(toNegate))
	if (unary->type == UnaryOperatorExpression::LogicalNegate)
	{
		return unary->operand;
	}
	return pool.allocate<UnaryOperatorExpression>(UnaryOperatorExpression::LogicalNegate, toNegate);
}

Statement* recursivelySimplifySequence(DumbAllocator& pool, SequenceNode* sequence)
{
	SequenceNode* simplified = pool.allocate<SequenceNode>(pool);
	
	// Combine redundant if-then-else blocks. At this point, we can assume that if conditions are single-term.
	for (Statement* stmt : sequence->statements)
	{
		if (auto thisIfElse = dyn_cast<IfElseNode>(stmt))
		{
			if (auto lastNode = simplified->statements.back_or_null())
			if (auto lastIfElse = dyn_cast_or_null<IfElseNode>(*lastNode))
			{
				if (lastIfElse->condition->isReferenceEqual(thisIfElse->condition))
				{
					lastIfElse->ifBody = appendStatements(pool, lastIfElse->ifBody, thisIfElse->ifBody);
					lastIfElse->elseBody = appendStatements(pool, lastIfElse->elseBody, thisIfElse->elseBody);
					recursivelySimplifyIfElse(pool, lastIfElse);
					continue;
				}
				else if (lastIfElse->condition->isReferenceEqual(wrapWithNegate(pool, thisIfElse->condition)))
				{
					lastIfElse->ifBody = appendStatements(pool, lastIfElse->ifBody, thisIfElse->elseBody);
					lastIfElse->elseBody = appendStatements(pool, lastIfElse->elseBody, thisIfElse->ifBody);
					recursivelySimplifyIfElse(pool, lastIfElse);
					continue;
				}
			}
			
			// If it wasn't merged, simplify the last-found if-else node and insert it.
			auto simplifiedIfElse = recursivelySimplifyStatement(pool, thisIfElse);
			simplified->statements.push_back(simplifiedIfElse);
		}
		else if (auto assignment = dyn_cast<AssignmentNode>(stmt))
		{
			if (assignment->right != TokenExpression::undefExpression)
			{
				simplified->statements.push_back(assignment);
			}
		}
		else
		{
			auto simplerStatement = recursivelySimplifyStatement(pool, stmt);
			if (auto subSeq = dyn_cast<SequenceNode>(simplerStatement))
			{
				if (subSeq->statements.size() > 0)
				{
					simplified->statements.push_back(subSeq->statements.begin(), subSeq->statements.end());
				}
			}
			else
			{
				simplified->statements.push_back(simplerStatement);
			}
		}
	}
	
	return simplified->statements.size() == 1 ? simplified->statements[0] : simplified;
}

Statement* recursivelySimplifyIfElse(DumbAllocator& pool, IfElseNode* ifElse)
{
	while (auto negated = dyn_cast<UnaryOperatorExpression>(ifElse->condition))
	{
		if (negated->type == UnaryOperatorExpression::LogicalNegate && ifElse->elseBody != nullptr)
		{
			ifElse->condition = negated->operand;
			swap(ifElse->ifBody, ifElse->elseBody);
		}
		else
		{
			break;
		}
	}
	
	ifElse->ifBody = recursivelySimplifyStatement(pool, ifElse->ifBody);
	if (ifElse->elseBody != nullptr)
	{
		ifElse->elseBody = recursivelySimplifyStatement(pool, ifElse->elseBody);
	}
	else if (auto childCond = dyn_cast<IfElseNode>(ifElse->ifBody))
	{
		if (childCond->elseBody == nullptr)
		{
			// Neither this if nor the nested if (which is the only child) has an else clause.
			// They can be combined into a single if with an && compound expression.
			auto merged = pool.allocate<NAryOperatorExpression>(pool, NAryOperatorExpression::ShortCircuitAnd);
			merged->addOperand(ifElse->condition);
			merged->addOperand(childCond->condition);
			ifElse->condition = merged;
			ifElse->ifBody = childCond->ifBody;
		}
	}
	
	return ifElse;
}

Statement* recursivelySimplifyLoop(DumbAllocator& pool, LoopNode* loop)
{
	loop->loopBody = recursivelySimplifyStatement(pool, loop->loopBody);
	while (true)
	{
		// The 6 patterns all start with an endless loop.
		if (loop->isEndless())
		{
			if (auto sequence = dyn_cast<SequenceNode>(loop->loopBody))
			{
				size_t lastIndex = sequence->statements.size();
				assert(lastIndex > 0);
				lastIndex--;
				
				if (auto ifElse = dyn_cast<IfElseNode>(sequence->statements[lastIndex]))
				{
					// DoWhile
					if (ifElse->ifBody == KeywordNode::breakNode)
					{
						loop->condition = wrapWithNegate(pool, ifElse->condition);
						loop->position = LoopNode::PostTested;
						removeBranch(pool, *sequence, lastIndex, true);
						continue;
					}
					else if (ifElse->elseBody == KeywordNode::breakNode)
					{
						loop->condition = ifElse->condition;
						loop->position = LoopNode::PostTested;
						removeBranch(pool, *sequence, lastIndex, false);
						continue;
					}
					
					// NestedDoWhile
					if (ifElse->elseBody == nullptr)
					{
						bool hasBreak = false;
						for (size_t i = 0; i < lastIndex; i++)
						{
							if (containsBreakStatement(sequence->statements[i]))
							{
								hasBreak = true;
								break;
							}
						}
						
						if (!hasBreak)
						{
							sequence->statements.erase_at(lastIndex);
							LoopNode* innerLoop = pool.allocate<LoopNode>(sequence);
							innerLoop->condition = wrapWithNegate(pool, ifElse->condition);
							Statement* simplified = recursivelySimplifyLoop(pool, innerLoop);
							
							auto outerLoopBody = pool.allocate<SequenceNode>(pool);
							outerLoopBody->statements.push_back(simplified);
							outerLoopBody->statements.push_back(ifElse->ifBody);
							loop->loopBody = outerLoopBody;
							continue;
						}
					}
				}
				
				// While
				if (auto ifElse = dyn_cast<IfElseNode>(sequence->statements[0]))
				{
					if (ifElse->ifBody == KeywordNode::breakNode)
					{
						loop->condition = wrapWithNegate(pool, ifElse->condition);
						loop->position = LoopNode::PreTested;
						removeBranch(pool, *sequence, 0, true);
						continue;
					}
					else if (ifElse->elseBody == KeywordNode::breakNode)
					{
						loop->condition = ifElse->condition;
						loop->position = LoopNode::PreTested;
						removeBranch(pool, *sequence, 0, false);
						continue;
					}
				}
				
				// Pretty sure that LoopToSeq can't happen with our pipeline.
			}
			else if (auto ifElse = dyn_cast<IfElseNode>(loop->loopBody))
			{
				// CondToSeq, CondToSeqNeg
				if (ifElse->ifBody != nullptr && ifElse->elseBody != nullptr)
				{
					bool trueHasBreak = containsBreakStatement(ifElse->ifBody);
					bool falseHasBreak = containsBreakStatement(ifElse->elseBody);
					if (trueHasBreak != falseHasBreak)
					{
						LoopNode* innerLoop;
						Statement* next;
						auto outerBody = pool.allocate<SequenceNode>(pool);
						if (falseHasBreak)
						{
							innerLoop = pool.allocate<LoopNode>(ifElse->ifBody);
							innerLoop->condition = ifElse->condition;
							next = ifElse->elseBody;
						}
						else
						{
							innerLoop = pool.allocate<LoopNode>(ifElse->elseBody);
							innerLoop->condition = wrapWithNegate(pool, ifElse->condition);
							next = ifElse->ifBody;
						}
						Statement* simplified = recursivelySimplifyLoop(pool, innerLoop);
						outerBody->statements.push_back(simplified);
						outerBody->statements.push_back(next);
						loop->loopBody = outerBody;
						continue;
					}
				}
			}
		}
		break;
	}
	
	return loop;
}

Statement* recursivelySimplifyStatement(DumbAllocator& pool, Statement* statement)
{
	switch (statement->getType())
	{
		case Statement::Sequence:
			return recursivelySimplifySequence(pool, cast<SequenceNode>(statement));
			
		case Statement::IfElse:
			return recursivelySimplifyIfElse(pool, cast<IfElseNode>(statement));
			
		case Statement::Loop:
			return recursivelySimplifyLoop(pool, cast<LoopNode>(statement));
			
		default: break;
	}
	return statement;
}

void recursivelySimplifyConditions(DumbAllocator& pool, Statement* statement)
{
	if (auto seq = dyn_cast<SequenceNode>(statement))
	{
		for (auto subStatement : seq->statements)
		{
			recursivelySimplifyConditions(pool, subStatement);
		}
	}
	else if (auto ifElse = dyn_cast<IfElseNode>(statement))
	{
		ifElse->condition = simplifyCondition(pool, ifElse->condition);
		recursivelySimplifyConditions(pool, ifElse->ifBody);
		if (ifElse->elseBody != nullptr)
		{
			recursivelySimplifyConditions(pool, ifElse->elseBody);
		}
	}
	else if (auto loop = dyn_cast<LoopNode>(statement))
	{
		loop->condition = simplifyCondition(pool, loop->condition);
		recursivelySimplifyConditions(pool, loop->loopBody);
	}
}
