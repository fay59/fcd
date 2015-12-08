//
// pass_flatten.cpp
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

#include "pass_flatten.h"

using namespace llvm;

namespace
{
	bool containsBreakStatement(Statement* statement)
	{
		if (statement == nullptr)
		{
			return false;
		}
		
		if (statement == KeywordStatement::breakNode)
		{
			return true;
		}
		
		if (auto seq = dyn_cast<SequenceStatement>(statement))
		{
			for (auto stmt : seq->statements)
			{
				if (containsBreakStatement(stmt))
					return true;
			}
		}
		else if (auto ifElse = dyn_cast<IfElseStatement>(statement))
		{
			return containsBreakStatement(ifElse->ifBody) || containsBreakStatement(ifElse->elseBody);
		}
		
		// Intentionally leaving out while statements, since a break in a while statement will not affect the outer
		// loop.
		return false;
	}
}

void AstFlatten::removeBranch(SequenceStatement &parent, size_t ifIndex, bool branch)
{
	IfElseStatement* ifElse = cast<IfElseStatement>(parent.statements[ifIndex]);
	if (branch)
	{
		// remove if body
		if (auto replacement = ifElse->elseBody)
		{
			ifElse->condition = negate(ifElse->condition);
			ifElse->ifBody = replacement;
			ifElse->elseBody = nullptr;
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

void AstFlatten::structurizeLoop(LoopStatement *loop)
{
	while (loop->isEndless())
	{
		if (auto sequence = dyn_cast<SequenceStatement>(loop->loopBody))
		{
			size_t lastIndex = sequence->statements.size();
			assert(lastIndex > 0);
			lastIndex--;
			
			if (auto ifElse = dyn_cast<IfElseStatement>(sequence->statements[lastIndex]))
			{
				// DoWhile
				if (ifElse->ifBody == KeywordStatement::breakNode)
				{
					loop->condition = negate(ifElse->condition);
					loop->position = LoopStatement::PostTested;
					removeBranch(*sequence, lastIndex, true);
					continue;
				}
				else if (ifElse->elseBody == KeywordStatement::breakNode)
				{
					loop->condition = ifElse->condition;
					loop->position = LoopStatement::PostTested;
					removeBranch(*sequence, lastIndex, false);
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
						LoopStatement* innerLoop = pool().allocate<LoopStatement>(sequence);
						innerLoop->condition = negate(ifElse->condition);
						Statement* simplified = flatten(innerLoop);
						
						auto outerLoopBody = pool().allocate<SequenceStatement>(pool());
						outerLoopBody->statements.push_back(simplified);
						outerLoopBody->statements.push_back(ifElse->ifBody);
						loop->loopBody = outerLoopBody;
						continue;
					}
				}
			}
			
			// While
			if (auto ifElse = dyn_cast<IfElseStatement>(sequence->statements[0]))
			{
				if (ifElse->ifBody == KeywordStatement::breakNode)
				{
					loop->condition = negate(ifElse->condition);
					loop->position = LoopStatement::PreTested;
					removeBranch(*sequence, 0, true);
					continue;
				}
				else if (ifElse->elseBody == KeywordStatement::breakNode)
				{
					loop->condition = ifElse->condition;
					loop->position = LoopStatement::PreTested;
					removeBranch(*sequence, 0, false);
					continue;
				}
			}
			
			// Pretty sure that LoopToSeq can't happen with our pipeline.
		}
		else if (auto ifElse = dyn_cast<IfElseStatement>(loop->loopBody))
		{
			// CondToSeq, CondToSeqNeg
			if (ifElse->ifBody != nullptr && ifElse->elseBody != nullptr)
			{
				bool trueHasBreak = containsBreakStatement(ifElse->ifBody);
				bool falseHasBreak = containsBreakStatement(ifElse->elseBody);
				if (trueHasBreak != falseHasBreak)
				{
					LoopStatement* innerLoop;
					Statement* next;
					auto outerBody = pool().allocate<SequenceStatement>(pool());
					if (falseHasBreak)
					{
						innerLoop = pool().allocate<LoopStatement>(ifElse->ifBody);
						innerLoop->condition = ifElse->condition;
						next = ifElse->elseBody;
					}
					else
					{
						innerLoop = pool().allocate<LoopStatement>(ifElse->elseBody);
						innerLoop->condition = negate(ifElse->condition);
						next = ifElse->ifBody;
					}
					Statement* simplified = flatten(innerLoop);
					outerBody->statements.push_back(simplified);
					outerBody->statements.push_back(next);
					loop->loopBody = outerBody;
					continue;
				}
			}
		}
		break;
	}
}

void AstFlatten::visitSequence(SequenceStatement* sequence)
{
	auto result = pool().allocate<SequenceStatement>(pool());
	for (Statement* statement : sequence->statements)
	{
		if (Statement* flattened = flatten(statement))
		{
			if (auto subSeq = dyn_cast<SequenceStatement>(flattened))
			{
				result->statements.push_back(subSeq->statements.begin(), subSeq->statements.end());
			}
			else
			{
				result->statements.push_back(flattened);
			}
		}
	}
	
	auto size = result->statements.size();
	if (size == 0)
	{
		intermediate = nullptr;
	}
	else if (size == 1)
	{
		intermediate = result->statements.front();
	}
	else
	{
		intermediate = result;
	}
}

void AstFlatten::visitIfElse(IfElseStatement* ifElse)
{
	Statement* flatIfBody = flatten(ifElse->ifBody);
	Statement* flatElseBody = flatten(ifElse->elseBody);
	if (flatIfBody == nullptr)
	{
		if (flatElseBody == nullptr)
		{
			intermediate = nullptr;
			return;
		}
		
		ifElse->condition = negate(ifElse->condition);
		ifElse->elseBody = flatElseBody;
	}
	else
	{
		ifElse->ifBody = flatIfBody;
		ifElse->elseBody = flatElseBody;
	}
	
	intermediate = ifElse;
}

void AstFlatten::visitLoop(LoopStatement* loop)
{
	if (Statement* flattened = flatten(loop->loopBody))
	{
		loop->loopBody = flattened;
		structurizeLoop(loop);
	}
	else
	{
		// can't assign an empty statement to a loop body, create an empty sequence
		loop->loopBody = pool().allocate<SequenceStatement>(pool());
	}
	intermediate = loop;
}

void AstFlatten::visitAssignment(AssignmentStatement *assignment)
{
	intermediate = assignment;
}

void AstFlatten::visitKeyword(KeywordStatement* keyword)
{
	intermediate = keyword;
}

void AstFlatten::visitExpression(ExpressionStatement* expression)
{
	intermediate = expression;
}

void AstFlatten::visitDeclaration(DeclarationStatement* declaration)
{
	intermediate = declaration;
}

const char* AstFlatten::getName() const
{
	return "Flatten AST";
}

void AstFlatten::doRun(FunctionNode &fn)
{
	fn.body = flatten(fn.body);
}
