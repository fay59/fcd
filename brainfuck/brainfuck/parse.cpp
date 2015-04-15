//
//  parse.cpp
//  brainfuck
//
//  Created by Félix on 2015-04-14.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include "parse.h"

using namespace std;

namespace brainfuck
{
	inst::inst(enum opcode o)
	: opcode(o)
	{
	}
	
	void inst::visit(statement_visitor &visitor)
	{
		visitor.visit(*this);
	}
	
	scope::scope(vector<unique_ptr<statement>> statements)
	: statements(move(statements))
	{
	}
	
	void scope::visit(statement_visitor &visitor)
	{
		visitor.visit(*this);
	}
	
	loop::loop(unique_ptr<scope> scope)
	: body(move(scope))
	{
	}
	
	void loop::visit(statement_visitor &visitor)
	{
		visitor.visit(*this);
	}
	
	void statement_visitor::visit(statement &statement)
	{
		statement.visit(*this);
	}
}
