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

void AstFlatten::visitSequence(SequenceNode* sequence)
{
	auto result = pool().allocate<SequenceNode>(pool());
	for (Statement* statement : sequence->statements)
	{
		if (Statement* flattened = flatten(statement))
		{
			if (auto subSeq = dyn_cast<SequenceNode>(flattened))
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

void AstFlatten::visitIfElse(IfElseNode* ifElse)
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

void AstFlatten::visitLoop(LoopNode* loop)
{
	if (Statement* flattened = flatten(loop->loopBody))
	{
		loop->loopBody = flattened;
	}
	else
	{
		// can't assign an empty statement to a loop body, create an empty sequence
		loop->loopBody = pool().allocate<SequenceNode>(pool());
	}
	intermediate = loop;
}

void AstFlatten::visitAssignment(AssignmentNode *assignment)
{
	intermediate = assignment;
}

void AstFlatten::visitKeyword(KeywordNode* keyword)
{
	intermediate = keyword;
}

void AstFlatten::visitExpression(ExpressionNode* expression)
{
	intermediate = expression;
}

void AstFlatten::visitDeclaration(DeclarationNode* declaration)
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
