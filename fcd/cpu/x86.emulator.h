//
// x86.emulator.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__x86_x86_emulator_h
#define fcd__x86_x86_emulator_h

#include <capstone/capstone.h>
#include "x86_regs.h"

static_assert(X86_INS_ENDING == 1295, "Fcd requires Capstone 3.0.4.");

#define PURE [[gnu::pure]]
#define NORETURN [[gnu::noreturn]]
#define PTR(t) [[gnu::nonnull]] t* __restrict__
#define CPTR(t) [[gnu::nonnull]] const t* __restrict__

#pragma mark - Intrinsic functions (handled by emulator)
extern "C" void x86_write_mem(x86_reg segment, uint64_t address, size_t size, uint64_t value);
extern "C" uint64_t x86_read_mem(x86_reg segment, uint64_t address, size_t size);
extern "C" void x86_call_intrin(CPTR(x86_config) config, PTR(x86_regs) regs, uint64_t target);
NORETURN extern "C" void x86_jump_intrin(CPTR(x86_config) config, PTR(x86_regs) regs, uint64_t target);
NORETURN extern "C" void x86_ret_intrin(CPTR(x86_config) config, PTR(x86_regs) regs);

NORETURN extern "C" void x86_assertion_failure(CPTR(char) problem);

#pragma mark - Implemented Functions

#define X86_INSTRUCTION_DEF(name)	\
	extern "C" void x86_##name( \
		CPTR(x86_config) config, \
		CPTR(cs_x86) inst, \
		PTR(x86_regs) regs, \
		PTR(x86_flags_reg) flags)

#define X86_INSTRUCTION_DECL(e, name)	\
	X86_INSTRUCTION_DEF(name);

#include "x86_insts.h"

extern const x86_reg_info x86_register_table[X86_REG_ENDING];

#endif /* fcd__x86_x86_emulator_h */
