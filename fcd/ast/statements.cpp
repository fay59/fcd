//
// statements.cpp
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

#include "statements.h"
#include "function.h"
#include "visitor.h"
#include "print.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

void NoopStatement::replaceChild(NOT_NULL(Statement) child, NOT_NULL(Statement) newChild)
{
	llvm_unreachable("noop statements cannot have children");
}

void ExpressionStatement::replaceChild(NOT_NULL(Statement) child, NOT_NULL(Statement) newChild)
{
	llvm_unreachable("expression statements cannot have children");
}

Statement* SequenceStatement::replace(iterator iter, NOT_NULL(Statement) newStatement)
{
	if (*iter == newStatement)
	{
		return nullptr;
	}
	
	Statement* old = *iter;
	disown(old);
	*iter = newStatement;
	takeChild(newStatement);
	return old;
}

void SequenceStatement::replaceChild(NOT_NULL(Statement) child, NOT_NULL(Statement) newChild)
{
	for (auto iter = statements.begin(); iter != statements.end(); ++iter)
	{
		if (*iter == child)
		{
			replace(iter, newChild);
			return;
		}
	}
	llvm_unreachable("child not found in sequence statement");
}

void SequenceStatement::pushBack(NOT_NULL(Statement) statement)
{
	takeChild(statement);
	statements.push_back(statement);
}

void SequenceStatement::takeAllFrom(SequenceStatement &sequence)
{
	for (Statement* statement : sequence)
	{
		sequence.disown(statement);
		takeChild(statement);
		statements.push_back(statement);
	}
	sequence.statements.clear();
}

void IfElseStatement::replaceChild(NOT_NULL(Statement) child, NOT_NULL(Statement) newChild)
{
	if (child == ifBody)
	{
		setIfBody(newChild);
		return;
	}
	if (child == elseBody)
	{
		setElseBody(newChild);
		return;
	}
	llvm_unreachable("child not found in if statement");
}

Statement* IfElseStatement::setIfBody(NOT_NULL(Statement) statement)
{
	Statement* old = ifBody;
	if (old == statement)
	{
		return nullptr;
	}
	
	if (old != nullptr)
	{
		disown(old);
	}
	ifBody = statement;
	takeChild(ifBody);
	return old;
}

Statement* IfElseStatement::setElseBody(Statement *statement)
{
	Statement* old = elseBody;
	if (old == statement)
	{
		return nullptr;
	}
	
	if (old != nullptr)
	{
		disown(old);
	}
	elseBody = statement;
	if (elseBody != nullptr)
	{
		takeChild(elseBody);
	}
	return old;
}

void LoopStatement::replaceChild(NOT_NULL(Statement) child, NOT_NULL(Statement) newChild)
{
	if (child == loopBody)
	{
		setLoopBody(newChild);
		return;
	}
	llvm_unreachable("child not found in loop statement");
}

Statement* LoopStatement::setLoopBody(NOT_NULL(Statement) statement)
{
	Statement* old = loopBody;
	if (old == statement)
	{
		return nullptr;
	}
	
	if (old != nullptr)
	{
		disown(old);
	}
	loopBody = statement;
	takeChild(loopBody);
	return old;
}

void KeywordStatement::replaceChild(NOT_NULL(Statement) child, NOT_NULL(Statement) newChild)
{
	llvm_unreachable("keyword statements cannot have children");
}
