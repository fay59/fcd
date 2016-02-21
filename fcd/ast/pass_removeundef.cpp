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

using namespace llvm;
using namespace std;

void AstRemoveUndef::visitAssignment(AssignmentStatement *assignment)
{
	if (assignment->right == TokenExpression::undefExpression)
	{
		toErase = assignment;
	}
	else
	{
		if (auto token = dyn_cast<TokenExpression>(assignment->left))
		{
			tokenInfo[token].assignments.push_back(assignment);
		}
		
		assignment->left->visit(*this);
		assignment->right->visit(*this);
	}
}

void AstRemoveUndef::visitSequence(SequenceStatement *sequence)
{
	// Visit sequences in reverse order. This allows us to delete values with dependences.
	auto& statements = sequence->statements;
	size_t i = statements.size();
	while (i != 0)
	{
		size_t current = i - 1;
		Statement* sub = statements[current];
		sub->visit(*this);
		if (toErase == sub)
		{
			statements.erase_at(current);
		}
		i = current;
	}
	
	if (statements.size() == 0)
	{
		toErase = sequence;
	}
}

void AstRemoveUndef::visitLoop(LoopStatement *loop)
{
	loop->loopBody->visit(*this);
	if (toErase == loop->loopBody)
	{
		toErase = loop;
	}
}

void AstRemoveUndef::visitIfElse(IfElseStatement *ifElse)
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

void AstRemoveUndef::visitToken(TokenExpression* token)
{
	tokenInfo[token].useCount++;
}

void AstRemoveUndef::doRun(FunctionNode &fn)
{
	// XXX: this is inefficient as there is no use list for statements (or expressions).
	// We need to walk over the AST twice, the first time to identify things to delete
	// and the second time to actually delete them.
	
	tokenInfo.clear();
	currentFunction = &fn;
	
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
		TokenExpression* token = (*iter)->name;
		const auto& info = tokenInfo[token];
		if (info.useCount == info.assignments.size())
		{
			for (auto assignment : info.assignments)
			{
				assignment->left = TokenExpression::undefExpression;
				assignment->right = TokenExpression::undefExpression;
			}
			iter = fn.erase(iter);
		}
		else
		{
			++iter;
		}
	}
	
	// Delete assignments that were undefined.
	fn.body->visit(*this);
}

const char* AstRemoveUndef::getName() const
{
	return "Remove undefined assignments";
}

AstRemoveUndef::~AstRemoveUndef()
{
}
