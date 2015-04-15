//
//  print.cpp
//  brainfuck
//
//  Created by Félix on 2015-04-14.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include "print.h"

using namespace std;

namespace brainfuck
{
	print_visitor::print_visitor(ostream& os)
	: os(os)
	{
	}
	
	void print_visitor::visit(inst &inst)
	{
		os << char(inst.opcode);
	}
	
	void print_visitor::visit(scope &scope)
	{
		for (auto& statement : scope.statements)
		{
			statement->visit(*this);
		}
	}
	
	void print_visitor::visit(loop& loop)
	{
		os << '[';
		loop.body->visit(*this);
		os << ']';
	}
}
