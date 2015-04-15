//
//  interp.cpp
//  brainfuck
//
//  Created by Félix on 2015-04-14.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <stdexcept>
#include <unistd.h>

#include "interp.h"

using namespace std;

namespace
{
	template<typename T, size_t N>
	constexpr size_t countof(T (&)[N])
	{
		return N;
	}
}

namespace brainfuck
{
	interp_visitor::interp_visitor(struct state& state)
	: state(state)
	{
	}
	
	void interp_visitor::visit(inst& inst)
	{
		switch (inst.opcode)
		{
			case opcode::dec_ptr:
				state.index = (state.index - 1) % countof(state.memory);
				break;
				
			case opcode::dec_value:
				state.memory[state.index]--;
				break;
				
			case opcode::inc_ptr:
				state.index = (state.index + 1) % countof(state.memory);
				break;
				
			case opcode::inc_value:
				state.memory[state.index]++;
				break;
				
			case opcode::input:
				read(state.fd_in, &state.memory[state.index], 1);
				break;
				
			case opcode::output:
				write(state.fd_out, &state.memory[state.index], 1);
				break;
				
			default:
				throw invalid_argument("inst");
		}
	}
	
	void interp_visitor::visit(scope& scope)
	{
		for (auto& statement : scope.statements)
		{
			visit(*statement);
		}
	}
	
	void interp_visitor::visit(loop& loop)
	{
		while (state.memory[state.index] != 0)
		{
			visit(*loop.body);
		}
	}
}
