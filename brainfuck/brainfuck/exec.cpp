//
//  compile.cpp
//  brainfuck
//
//  Created by Félix on 2015-04-15.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include "exec.h"

using namespace std;

namespace brainfuck
{
	void to_executable_visitor::visit(inst& inst)
	{
		executable.emplace_back(inst.opcode);
	}
	
	void to_executable_visitor::visit(scope& scope)
	{
		for (auto& statement : scope.statements)
		{
			visit(*statement);
		}
	}
	
	void to_executable_visitor::visit(loop& loop)
	{
		size_t start_index = executable.size();
		executable.emplace_back(opcode::loop_enter);
		visit(*loop.body);
		size_t end_index = executable.size();
		executable.emplace_back(opcode::loop_exit);
		
		executable[start_index].data = end_index + 1;
		executable[end_index].data = start_index + 1;
	}
	
	vector<executable_statement> to_executable_visitor::code()
	{
		vector<executable_statement> temp;
		executable.swap(temp);
		return move(temp);
	}
	
	void execute(const vector<executable_statement>& statements)
	{
		execute(statements, execute_one);
	}
}

extern "C" void go_to([[gnu::nonnull]] brainfuck::state* __restrict__ state, size_t dest)
{
	state->ip = dest;
}
