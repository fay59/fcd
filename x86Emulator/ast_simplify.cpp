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
		IfElseNode* ifElse = cast<IfElseNode>(parent.statements[ifIndex]);
		if (branch)
		{
			// remove if body
			if (auto replacement = ifElse->elseBody)
			{
				ifElse->condition = wrapWithNegate(pool, ifElse->condition);
				ifElse->ifBody = replacement;
			}
			else
			{
				parent.statements.erase_at(ifIndex);
			}
		}
		else
		{
			// remove else
			ifElse->elseBody = nullptr;
		}
	}
	
	NAryOperatorExpression* changeOperator(DumbAllocator& pool, NAryOperatorExpression* expr, NAryOperatorExpression::NAryOperatorType op)
	{
		auto result = pool.allocate<NAryOperatorExpression>(pool, op);
		result->addOperands(expr->operands.begin(), expr->operands.end());
		return result;
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
	
	class AstSimplifier
	{
		DumbAllocator& pool;
		
	public:
		AstSimplifier(DumbAllocator& pool) : pool(pool)
		{
		}
		
		Expression* simplifyNegation(UnaryOperatorExpression* negation);
		Expression* simplifyCondition(Expression* expression);
		
		Statement* simplifySequence(SequenceNode* sequence);
		IfElseNode* simplifyIfElse(IfElseNode* ifElse);
		LoopNode* simplifyLoop(LoopNode* loop);
		Statement* simplifyStatement(Statement* statement);
	};
}

Expression* AstSimplifier::simplifyNegation(UnaryOperatorExpression* negated)
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

Expression* AstSimplifier::simplifyCondition(Expression* expr)
{
	if (auto unary = dyn_cast<UnaryOperatorExpression>(expr))
	{
		if (unary->type == UnaryOperatorExpression::LogicalNegate)
		{
			return simplifyNegation(unary);
		}
	}
	else if (auto nary = dyn_cast<NAryOperatorExpression>(expr))
	{
		for (auto& subExpression : nary->operands)
		{
			subExpression = simplifyCondition(subExpression);
		}
	}
	return expr;
}

Statement* AstSimplifier::simplifySequence(SequenceNode* sequence)
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
					simplifyIfElse(lastIfElse);
					continue;
				}
				else if (lastIfElse->condition->isReferenceEqual(wrapWithNegate(pool, thisIfElse->condition)))
				{
					lastIfElse->ifBody = appendStatements(pool, lastIfElse->ifBody, thisIfElse->elseBody);
					lastIfElse->elseBody = appendStatements(pool, lastIfElse->elseBody, thisIfElse->ifBody);
					simplifyIfElse(lastIfElse);
					continue;
				}
			}
			
			// If it wasn't merged, simplify the current if-else node and insert it.
			auto simplifiedIfElse = simplifyIfElse(thisIfElse);
			simplified->statements.push_back(simplifiedIfElse);
		}
		else if (auto assignment = dyn_cast<AssignmentNode>(stmt))
		{
			auto left = assignment->left;
			auto right = assignment->right;
			if (right != TokenExpression::undefExpression && !left->isReferenceEqual(right))
			{
				simplified->statements.push_back(assignment);
			}
		}
		else
		{
			auto simplerStatement = simplifyStatement(stmt);
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

IfElseNode* AstSimplifier::simplifyIfElse(IfElseNode* ifElse)
{
	// Remove spurious negations.
	while (auto negated = dyn_cast<UnaryOperatorExpression>(ifElse->condition))
	{
		if (negated->type == UnaryOperatorExpression::LogicalNegate && ifElse->elseBody != nullptr)
		{
			ifElse->condition = negated->operand;
			auto elseBody = ifElse->elseBody;
			ifElse->elseBody = ifElse->ifBody;
			ifElse->ifBody = elseBody;
		}
		else
		{
			break;
		}
	}
	
	ifElse->ifBody = simplifyStatement(ifElse->ifBody);
	if (ifElse->elseBody != nullptr)
	{
		ifElse->elseBody = simplifyStatement(ifElse->elseBody);
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

LoopNode* AstSimplifier::simplifyLoop(LoopNode* loop)
{
	loop->condition = simplifyCondition(loop->condition);
	loop->loopBody = simplifyStatement(loop->loopBody);
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
						bool hasBreak = any_of(sequence->statements.begin(), sequence->statements.end(), [&](Statement* stmt)
						{
							return containsBreakStatement(stmt);
						});
						
						if (!hasBreak)
						{
							sequence->statements.erase_at(lastIndex);
							LoopNode* innerLoop = pool.allocate<LoopNode>(sequence);
							innerLoop->condition = wrapWithNegate(pool, ifElse->condition);
							Statement* simplified = simplifyLoop(innerLoop);
							
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
						Statement* simplified = simplifyLoop(innerLoop);
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

Statement* AstSimplifier::simplifyStatement(Statement* statement)
{
	switch (statement->getType())
	{
		case Statement::Sequence:
			return simplifySequence(cast<SequenceNode>(statement));
			
		case Statement::IfElse:
			return simplifyIfElse(cast<IfElseNode>(statement));
			
		case Statement::Loop:
			return simplifyLoop(cast<LoopNode>(statement));
			
		default: break;
	}
	return statement;
}

Expression* wrapWithNegate(DumbAllocator& pool, Expression* toNegate)
{
	if (auto unary = dyn_cast<UnaryOperatorExpression>(toNegate))
	if (unary->type == UnaryOperatorExpression::LogicalNegate)
	{
		return unary->operand;
	}
	return pool.allocate<UnaryOperatorExpression>(UnaryOperatorExpression::LogicalNegate, toNegate);
}

Statement* recursivelySimplifyStatement(DumbAllocator& pool, Statement* statement)
{
	AstSimplifier simplifier(pool);
	return simplifier.simplifyStatement(statement);
}
