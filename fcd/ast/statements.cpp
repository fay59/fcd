//
// statements.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "statements.h"
#include "function.h"
#include "visitor.h"
#include "print.h"

#include <llvm/Support/raw_os_ostream.h>

using namespace llvm;
using namespace std;

StatementList::StatementIterator& StatementList::StatementIterator::operator++()
{
	current = current->next;
	return *this;
}

StatementList::StatementIterator& StatementList::StatementIterator::operator--()
{
	current = current->previous;
	return *this;
}

StatementList::StatementList(initializer_list<Statement*> statements)
: StatementList(nullptr)
{
	for (auto statement : statements)
	{
		insert(end(), statement);
	}
}

void StatementList::insert(NOT_NULL(Statement) location, NOT_NULL(Statement) statement)
{
	location->list->insert(StatementIterator(location), statement);
}

void StatementList::insert(StatementIterator iter, NOT_NULL(Statement) statement)
{
	assert(statement->list == nullptr);
	Statement* next = *iter;
	
	if (next == nullptr)
	{
		// insert at end
		if (last == nullptr)
		{
			first = statement;
		}
		else
		{
			statement->previous = last;
			last->next = statement;
		}
		last = statement;
	}
	else
	{
		assert(next->list == this);
		if (Statement* prev = next->previous)
		{
			prev->next = statement;
			next->previous = statement;
		}
		else
		{
			// insert at beginning
			assert(first != nullptr); // already covered above
			statement->next = first;
			first->previous = statement;
			first = statement;
		}
	}
}

void StatementList::erase(NOT_NULL(Statement) statement)
{
	(void) statement->list->erase(StatementIterator(statement));
}

StatementList::StatementIterator StatementList::erase(StatementIterator iter)
{
	Statement* target = *iter;
	assert(target->list == this);
	
	Statement* oldPrev = target->previous;
	Statement* oldNext = target->next;
	(oldPrev == nullptr ? first : oldPrev->next) = target->next;
	(oldNext == nullptr ? last : oldNext->previous) = target->previous;
	target->previous = nullptr;
	target->next = nullptr;
	
	return StatementIterator(oldNext);
}

void StatementList::clear()
{
	for (Statement* statement : *this)
	{
		statement->dropAllReferences();
	}
	first = nullptr;
	last = nullptr;
}

void IfElseStatement::dropAllStatementReferences()
{
	ifBody.clear();
	elseBody.clear();
}

void LoopStatement::dropAllStatementReferences()
{
	loopBody.clear();
}
