//
//  interp.h
//  brainfuck
//
//  Created by Félix on 2015-04-14.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __brainfuck__interp__
#define __brainfuck__interp__

#include <cstddef>
#include <iostream>

#include "parse.h"

namespace brainfuck
{
	struct state
	{
		unsigned char memory[0x1000];
		size_t index;
		int fd_in;
		int fd_out;
	};
	
	class interp_visitor : public statement_visitor
	{
		state& state;
		
	public:
		interp_visitor(struct state& state);
		
		using statement_visitor::visit;
		virtual void visit(inst& inst) override;
		virtual void visit(scope& scope) override;
		virtual void visit(loop& loop) override;
	};
}

#define BF_DECLARE(cmd) [[gnu::noinline]] extern "C" void bf_ ## cmd ([[gnu::nonnull]] bf_state* __restrict__ state)
#define BF_IMPL(cmd) BF_DECLARE(cmd)

#endif /* defined(__brainfuck__interp__) */
