//
// ast_pass_flatten.cpp
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

#include "ast_pass_flatten.h"

using namespace llvm;

Statement* AstFlatten::flatten(SequenceNode* sequence)
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
		return nullptr;
	}
	else if (size == 1)
	{
		return result->statements.front();
	}
	else
	{
		return result;
	}
}

Statement* AstFlatten::flatten(IfElseNode* ifElse)
{
	Statement* flatIfBody = flatten(ifElse->ifBody);
	Statement* flatElseBody = flatten(ifElse->elseBody);
	if (flatIfBody == nullptr)
	{
		if (flatElseBody == nullptr)
		{
			return nullptr;
		}
		
		ifElse->condition = negate(ifElse->condition);
		ifElse->elseBody = flatElseBody;
	}
	else
	{
		ifElse->ifBody = flatIfBody;
		ifElse->elseBody = flatElseBody;
	}
	return ifElse;
}

Statement* AstFlatten::flatten(LoopNode* loop)
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
	return loop;
}

Statement* AstFlatten::flatten(Statement* base)
{
	if (base == nullptr)
	{
		return nullptr;
	}
	
	if (auto seq = dyn_cast<SequenceNode>(base))
	{
		return flatten(seq);
	}
	else if (auto ifElse = dyn_cast<IfElseNode>(base))
	{
		return flatten(ifElse);
	}
	else if (auto loop = dyn_cast<LoopNode>(base))
	{
		return flatten(loop);
	}
	return base;
}

const char* AstFlatten::getName() const
{
	return "Flatten AST";
}

void AstFlatten::doRun(FunctionNode &fn)
{
	fn.body = flatten(fn.body);
}
