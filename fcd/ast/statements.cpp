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

StatementList::StatementList(Statement* parent, initializer_list<Statement*> statements)
: StatementList(parent)
{
	for (auto statement : statements)
	{
		insert(end(), statement);
	}
}

Statement* StatementList::pop_front()
{
	Statement* result = first;
	result->list = nullptr;
	first = first->next;
	(first == nullptr ? last : first->previous) = nullptr;
	return result;
}

Statement* StatementList::pop_back()
{
	Statement* result = last;
	result->list = nullptr;
	last = last->previous;
	(last == nullptr ? first : last->next) = nullptr;
	return result;
}

StatementList& StatementList::operator=(StatementList&& that)
{
	for (Statement* stmt : *this)
	{
		stmt->dropAllReferences();
		stmt->list = nullptr;
		stmt->previous = nullptr;
		stmt->next = nullptr;
	}
	
	first = that.first;
	last = that.last;
	that.first = nullptr;
	that.last = nullptr;
	return *this;
}

void StatementList::insert(NOT_NULL(Statement) location, NOT_NULL(Statement) statement)
{
	location->list->insert(iterator(location), statement);
}

void StatementList::insert(iterator iter, NOT_NULL(Statement) statement)
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
	
	statement->list = this;
}

void StatementList::insert(iterator iter, StatementList &&that)
{
	while (!that.empty())
	{
		Statement* first = that.front();
		erase(first);
		insert(iter, first);
	}
}

void StatementList::push_front(NOT_NULL(Statement) statement)
{
	assert(statement->list == nullptr);
	if (first == nullptr)
	{
		last = statement;
	}
	else
	{
		first->previous = statement;
		statement->next = first;
	}
	first = statement;
	first->list = this;
}

void StatementList::push_front(StatementList&& that)
{
	while (!that.empty())
	{
		Statement* first = that.front();
		erase(first);
		push_front(first);
	}
}

void StatementList::push_back(NOT_NULL(Statement) statement)
{
	assert(statement->list == nullptr);
	if (last == nullptr)
	{
		first = statement;
	}
	else
	{
		last->next = statement;
		statement->next = last;
	}
	last = statement;
	last->list = this;
}

void StatementList::push_back(StatementList&& that)
{
	while (!that.empty())
	{
		Statement* first = that.front();
		erase(first);
		push_back(first);
	}
}

void StatementList::erase(NOT_NULL(Statement) statement)
{
	if (statement->list != nullptr)
	{
		(void) statement->list->erase(iterator(statement));
	}
}

StatementList::iterator StatementList::erase(iterator iter)
{
	Statement* target = *iter;
	assert(target->list == this);
	
	Statement* oldPrev = target->previous;
	Statement* oldNext = target->next;
	(oldPrev == nullptr ? first : oldPrev->next) = target->next;
	(oldNext == nullptr ? last : oldNext->previous) = target->previous;
	target->previous = nullptr;
	target->next = nullptr;
	target->list = nullptr;
	
	return iterator(oldNext);
}

void StatementList::clear()
{
	for (Statement* statement : *this)
	{
		statement->dropAllReferences();
		statement->previous = nullptr;
		statement->next = nullptr;
		statement->list = nullptr;
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
