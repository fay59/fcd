//
// pass_removeundef.cpp
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

#include "pass_removeundef.h"

void AstRemoveUndef::visitAssignment(AssignmentNode *assignment)
{
	if (assignment->right == TokenExpression::undefExpression)
	{
		toErase = assignment;
	}
}

void AstRemoveUndef::visitSequence(SequenceNode *sequence)
{
	size_t i = 0;
	auto& statements = sequence->statements;
	while (i < statements.size())
	{
		Statement* sub = statements[i];
		sub->visit(*this);
		if (toErase == sub)
		{
			statements.erase_at(i);
		}
		else
		{
			++i;
		}
	}
	
	if (statements.size() == 0)
	{
		toErase = sequence;
	}
}

void AstRemoveUndef::visitLoop(LoopNode *loop)
{
	loop->loopBody->visit(*this);
	if (toErase == loop->loopBody)
	{
		toErase = loop;
	}
}

void AstRemoveUndef::visitIfElse(IfElseNode *ifElse)
{
	if (auto elseBody = ifElse->elseBody)
	{
		elseBody->visit(*this);
		if (toErase == elseBody)
		{
			ifElse->elseBody = nullptr;
		}
	}
	
	ifElse->ifBody->visit(*this);
	if (toErase == ifElse->ifBody)
	{
		if (auto elseBody = ifElse->elseBody)
		{
			ifElse->condition = negate(ifElse->condition);
			ifElse->ifBody = elseBody;
			ifElse->elseBody = nullptr;
		}
		else
		{
			toErase = ifElse;
		}
	}
}

void AstRemoveUndef::doRun(FunctionNode &fn)
{
	// Remove undefined statements.
	fn.body->visit(*this);
	if (toErase == fn.body)
	{
		fn.body = nullptr;
	}
	
	// Remove unused declarations.
	auto iter = fn.decls_begin();
	while (iter != fn.decls_end())
	{
		if (auto refs = useAnalysis.getReferences((*iter)->name))
		{
			if (refs->uses.size() + refs->defs.size() == 0)
			{
				iter = fn.erase(iter);
			}
			else
			{
				++iter;
			}
		}
	}
}

const char* AstRemoveUndef::getName() const
{
	return "Remove undefined assignments";
}
