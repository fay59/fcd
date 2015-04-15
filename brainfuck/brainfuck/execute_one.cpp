//
//  execute_one.cpp
//  brainfuck
//
//  Created by Félix on 2015-04-15.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <iostream>

#include "exec.h"

using namespace brainfuck;

#define BF_OPCODE(op) static void op ([[gnu::nonnull]] state* __restrict__ state, executable_statement statement)

namespace
{
	template<typename T, size_t N>
	constexpr size_t countof(T (&)[N])
	{
		return N;
	}
	
	BF_OPCODE(dec_ptr)
	{
		state->index = (state->index - 1) % countof(state->memory);
	}
	
	BF_OPCODE(dec_value)
	{
		state->memory[state->index]--;
	}
	
	BF_OPCODE(inc_ptr)
	{
		state->index = (state->index + 1) % countof(state->memory);
	}
	
	BF_OPCODE(inc_value)
	{
		state->memory[state->index]++;
	}
	
	BF_OPCODE(input)
	{
		state->memory[state->index] = getchar();
	}
	
	BF_OPCODE(output)
	{
		putchar(state->memory[state->index]);
	}
	
	BF_OPCODE(loop_enter)
	{
		if (state->memory[state->index] == 0)
		{
			go_to(state, statement.data);
		}
	}
	
	BF_OPCODE(loop_exit)
	{
		if (state->memory[state->index] != 0)
		{
			go_to(state, statement.data);
		}
	}
	
#define BF_OP_TABLE_ENTRY(n) [char(opcode::n)] = &n
	void (*opcode_table[256])([[gnu::nonnull]] state* __restrict__, executable_statement) = {
		BF_OP_TABLE_ENTRY(dec_ptr),
		BF_OP_TABLE_ENTRY(dec_value),
		BF_OP_TABLE_ENTRY(inc_ptr),
		BF_OP_TABLE_ENTRY(inc_value),
		BF_OP_TABLE_ENTRY(input),
		BF_OP_TABLE_ENTRY(output),
		BF_OP_TABLE_ENTRY(loop_enter),
		BF_OP_TABLE_ENTRY(loop_exit),
	};
}

extern "C" void brainfuck::execute_one([[gnu::nonnull]] state* __restrict__ state, executable_statement statement)
{
	if (auto function = opcode_table[char(statement.opcode)])
	{
		function(state, statement);
	}
}
