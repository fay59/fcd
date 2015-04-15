//
//  execute_one.cpp
//  brainfuck
//
//  Created by Félix on 2015-04-15.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <cstdio>

#include "exec.h"

using namespace brainfuck;

#define BF_OPCODE(op) extern "C" void op ([[gnu::nonnull]] state* __restrict__ state, executable_statement statement) noexcept

namespace
{
	template<typename T, size_t N>
	constexpr size_t countof(T (&)[N])
	{
		return N;
	}
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

extern "C" void brainfuck::execute_one([[gnu::nonnull]] state* __restrict__ state, executable_statement statement) noexcept
{
#define OP_CASE(n)	case opcode::n: n(state, statement); break
	switch (statement.opcode)
	{
		OP_CASE(dec_ptr);
		OP_CASE(dec_value);
		OP_CASE(inc_ptr);
		OP_CASE(inc_value);
		OP_CASE(input);
		OP_CASE(output);
		OP_CASE(loop_enter);
		OP_CASE(loop_exit);
		default: break;
	}
}
