//
// x86_emulator.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is part of fcd.
// 
// fcd is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// fcd is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with fcd.  If not, see <http://www.gnu.org/licenses/>.
//

#ifndef fcd__x86_x86_emulator_h
#define fcd__x86_x86_emulator_h

#include "Capstone.h"

union x86_word_reg {
	uint16_t word;
	struct {
		uint8_t low;
		uint8_t high;
	};
};

union x86_dword_reg {
	uint32_t dword;
	struct {
		x86_word_reg low;
		x86_word_reg high;
	};
};

union x86_qword_reg {
	uint64_t qword;
	struct {
		x86_dword_reg low;
		x86_dword_reg high;
	};
};

union x86_mm_reg {
	double d[8];
	float f[16];
	
	uint64_t l[8];
	uint32_t i[16];
	uint16_t s[32];
	uint8_t b[64];
};

struct x86_flags_reg {
	// status flags
	bool cf; // carry: set to true when an arithmetic carry occurs
	bool pf; // parity: set to true if number of bits set in the result is even
	bool af; // adjust: set to true if operation on least significant 4 bits caused carry
	bool zf; // zero: set if operation result is 0
	bool sf; // sign: set if most significant bit of result is 1
	bool of; // overflow: set when the result has a sign different from the expected one (carry into ^ carry out)
	
	// control/system flags
	/*
	bool tf; // trap; single-step
	bool if_; // interrupt
	bool df; // direction
	bool iopl; // I/O privilege level, always 1
	bool nt; // nested task flag, always 1
	bool rf; // resume flag
	bool vm; // virtual mode
	bool ac; // alignment check
	bool vif; // virtual interrupt flag
	bool vip; // virtual interrupt pending
	bool id; // can use cpuid
	*/
};

struct x86_regs {
	x86_qword_reg zero; // eiz/riz pseudo-registers
	x86_qword_reg a, b, c, d;
	x86_qword_reg si, di;
	x86_qword_reg bp, sp, ip;
	x86_qword_reg r8, r9, r10, r11, r12, r13, r14, r15;
	x86_qword_reg cs, ds, es, fs, gs, ss;
	
	// AVX512 mask registers
	//x86_qword_reg k0, k1, k2, k3, k4, k5, k6, k7;
	
	// Crazy large amount of multimedia registers
	//x86_mm_reg mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7;
	//x86_mm_reg mm8, mm9, mm10, mm11, mm12, mm13, mm14, mm15;
	//x86_mm_reg mm16, mm17, mm18, mm19, mm20, mm21, mm22, mm23;
	//x86_mm_reg mm24, mm25, mm26, mm27, mm28, mm29, mm30, mm31;
	
	// As far as I can tell, FP registers are an LLVM invention that are only ever implicitly used.
	// QwordRegister fp0, fp1, fp2, fp3, fp4, fp5, fp6, fp7, fp8;
	
	// Exclude control and debug registers
	//QwordRegister cr0, cr1, cr2, cr3, cr4, cr5, cr6, cr7, cr8, cr9, cr10, cr11, cr12, cr13, cr14, cr15;
	//QwordRegister dr0, dr1, dr2, dr3, dr4, dr5, dr6, dr7;
};

enum class x86_reg_type {
	qword_reg,
	mm_reg,
	enum_count,
};

struct x86_reg_selector {
	x86_qword_reg x86_regs::*qword;
	x86_dword_reg x86_qword_reg::*dword;
	x86_word_reg x86_dword_reg::*word;
	uint8_t x86_word_reg::*byte;
};

struct x86_reg_info {
	union {
		x86_reg_selector reg;
		x86_mm_reg x86_regs::*mm;
	};
	
	size_t size;
	x86_reg_type type;
};

enum x86_isa : uint32_t {
	x86_isa16 = 16,
	x86_isa32 = 32,
	x86_isa64 = 64,
};

struct x86_config {
	x86_isa isa;
	size_t address_size;
	x86_reg ip;
	x86_reg sp;
	x86_reg fp;
};

#define PURE [[gnu::pure]]
#define NORETURN [[gnu::noreturn]]
#define PTR(t) [[gnu::nonnull]] t* __restrict__
#define CPTR(t) [[gnu::nonnull]] const t* __restrict__

#pragma mark - Intrinsic functions (handled by emulator)
extern "C" void x86_write_mem(uint64_t address, size_t size, uint64_t value);
extern "C" uint64_t x86_read_mem(uint64_t address, size_t size);
extern "C" void x86_call_intrin(CPTR(x86_config) config, PTR(x86_regs) regs, uint64_t target);
NORETURN extern "C" void x86_jump_intrin(CPTR(x86_config) config, PTR(x86_regs) regs, uint64_t target);
NORETURN extern "C" void x86_ret_intrin(CPTR(x86_config) config, PTR(x86_regs) regs);

NORETURN extern "C" void x86_assertion_failure(CPTR(char) problem);
NORETURN extern "C" void x86_unimplemented(PTR(x86_regs) regs, CPTR(char) inst);

#pragma mark - Implemented Functions

#define X86_INSTRUCTION_DEF(name)	\
	extern "C" void x86_##name( \
		CPTR(x86_config) config, \
		CPTR(cs_x86) inst, \
		PTR(x86_regs) regs, \
		PTR(x86_flags_reg) flags)

#define X86_INSTRUCTION_DECL(e, name)	\
	X86_INSTRUCTION_DEF(name);

#include "x86_defs.h"

extern const x86_reg_info x86_register_table[X86_REG_ENDING];

#endif /* fcd__x86_x86_emulator_h */
