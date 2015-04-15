//
//  compile.h
//  brainfuck
//
//  Created by Félix on 2015-04-15.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __brainfuck__compile__
#define __brainfuck__compile__

#include <cstdint>
#include <cstddef>
#include <vector>

#include "parse.h"

namespace brainfuck
{
	struct executable_statement
	{
		unsigned data;
		opcode opcode;
		
		constexpr executable_statement(enum opcode opcode)
		: data(0), opcode(opcode)
		{
		}
	};
	
	struct state
	{
		uint8_t memory[0x1000];
		size_t index;
		unsigned ip;
	};
	
	class to_executable_visitor : statement_visitor
	{
		std::vector<executable_statement> executable;
		
	public:
		using statement_visitor::visit;
		virtual void visit(inst& inst) override;
		virtual void visit(scope& scope) override;
		virtual void visit(loop& loop) override;
		
		std::vector<executable_statement> code();
	};
	
	extern "C" void execute_one([[gnu::nonnull]] state* __restrict__ state, executable_statement statement) noexcept;
	extern "C" void go_to([[gnu::nonnull]] state* __restrict__ state, unsigned dest) noexcept;
	
	template<typename TExec>
	void execute(const std::vector<executable_statement>& code, TExec&& exec)
	{
		state state = {0};
		while (state.ip != code.size())
		{
			const auto& statement = code[state.ip];
			state.ip++;
			exec(&state, statement);
		}
	}
}

#endif /* defined(__brainfuck__compile__) */
