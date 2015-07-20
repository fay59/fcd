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
		static constexpr Statement* IfElseNode::*branchSelector[] = { &IfElseNode::ifBody, &IfElseNode::elseBody };
		size_t selectorIndex = !!branch; // make sure that branch is either 0 or 1
		
		IfElseNode* ifElse = cast<IfElseNode>(parent.statements[ifIndex]);
		ifElse->*branchSelector[selectorIndex] = ifElse->*branchSelector[!selectorIndex];
		if (ifElse->*branchSelector[selectorIndex] != nullptr)
		{
			ifElse->*branchSelector[!selectorIndex] = nullptr;
			ifElse->condition = logicalNegate(pool, ifElse->condition);
		}
		else
		{
			parent.statements.erase_at(ifIndex);
		}
	}
}

Statement* recursivelySimplifyIfElse(DumbAllocator& pool, IfElseNode* statement);

Expression* logicalNegate(DumbAllocator& pool, Expression* toNegate)
{
	if (auto unary = dyn_cast<UnaryOperatorExpression>(toNegate))
	{
		if (unary->type == UnaryOperatorExpression::LogicalNegate)
		{
			return unary->operand;
		}
	}
	return pool.allocate<UnaryOperatorExpression>(UnaryOperatorExpression::LogicalNegate, toNegate);
}

Statement* recursivelySimplifySequence(DumbAllocator& pool, SequenceNode* sequence)
{
	SequenceNode* simplified = pool.allocate<SequenceNode>(pool);
	
	// Combine redundant if-then-else blocks. At this point, we can assume that if conditions are single-term.
	IfElseNode* lastIfElse;
	IfElseNode* thisIfElse = nullptr;
	for (Statement* stmt : sequence->statements)
	{
		lastIfElse = thisIfElse;
		if ((thisIfElse = dyn_cast<IfElseNode>(stmt)))
		{
			if (lastIfElse != nullptr)
			{
				if (lastIfElse->condition->isReferenceEqual(thisIfElse->condition))
				{
					auto newSeq = pool.allocate<SequenceNode>(pool);
					newSeq->statements.push_back(lastIfElse->ifBody);
					newSeq->statements.push_back(thisIfElse->ifBody);
					lastIfElse->ifBody = newSeq;
					recursivelySimplifyIfElse(pool, lastIfElse);
					continue;
				}
				else if (lastIfElse->condition->isReferenceEqual(logicalNegate(pool, thisIfElse->condition)))
				{
					if (lastIfElse->elseBody == nullptr)
					{
						lastIfElse->elseBody = thisIfElse->ifBody;
					}
					else
					{
						auto newSeq = pool.allocate<SequenceNode>(pool);
						newSeq->statements.push_back(lastIfElse->elseBody);
						newSeq->statements.push_back(thisIfElse->ifBody);
						lastIfElse->elseBody = newSeq;
					}
					recursivelySimplifyIfElse(pool, lastIfElse);
					continue;
				}
			}
			
			// If it wasn't merged, simplify the last-found if-else node and insert it.
			auto simplifiedIfElse = recursivelySimplifyStatement(pool, thisIfElse);
			simplified->statements.push_back(simplifiedIfElse);
		}
		else
		{
			auto simplerStatement = recursivelySimplifyStatement(pool, stmt);
			if (auto subSeq = dyn_cast<SequenceNode>(simplerStatement))
			{
				if (subSeq->statements.size() > 0)
				{
					simplified->statements.push_back(subSeq->statements.begin(), subSeq->statements.end());
					thisIfElse = dyn_cast<IfElseNode>(simplified->statements.back());
				}
				else
				{
					thisIfElse = nullptr;
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
						loop->condition = logicalNegate(pool, ifElse->condition);
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
							innerLoop->condition = logicalNegate(pool, ifElse->condition);
							auto outerLoopBody = pool.allocate<SequenceNode>(pool);
							outerLoopBody->statements.push_back(innerLoop);
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
						loop->condition = logicalNegate(pool, ifElse->condition);
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
							innerLoop->condition = logicalNegate(pool, ifElse->condition);
							next = ifElse->ifBody;
						}
						outerBody->statements.push_back(innerLoop);
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
