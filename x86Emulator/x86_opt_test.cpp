//
//  x86_opt_test.cpp
//  x86Emulator
//
//  Created by Félix on 2015-04-09.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#define INLINE_FOR_TESTS [[gnu::always_inline]]

#include "x86_emulator.cpp"

extern "C" x86_qword_reg x86_clobber_reg(const cs_x86_op* reg_list, size_t reg_list_count)
{
	return x86_qword_reg();
}

extern "C" x86_mm_reg x86_clobber_mmr(const cs_x86_op* reg_list, size_t reg_list_count)
{
	return x86_mm_reg();
}

extern "C" void x86_clobber_mem(const cs_x86_op* destination, const cs_x86_op* reg_list, size_t reg_list_count)
{
	
}

extern "C" void x86_write_mem(uint64_t address, size_t size, uint64_t value)
{
	
}

extern "C" uint64_t x86_read_mem(uint64_t address, size_t size)
{
	return address;
}

extern "C" void x86_call_intrin(uint64_t target, x86_regs* __restrict__ regs)
{
	
}

extern "C" void x86_ret_intrin(x86_regs* __restrict__ regs)
{
	
}

[[gnu::noreturn]]
extern "C" void x86_assertion_failure(const char* problem)
{
	puts(problem);
	exit(1);
}

extern "C" void x86_unimplemented(const cs_x86* inst, x86_regs* __restrict__ regs)
{
	puts("not implemented");
}

struct cs_everything
{
	x86_insn code;
	cs_x86 x86;
};

constexpr cs_x86 operands[] = {
	{
		// insn(X86_INS_ADD, X86_REG_RAX, 0xdeadbeef),
		.op_count = 2,
		.operands = {
			{ .type = X86_OP_REG, .size = 8, .reg = X86_REG_RAX },
			{ .type = X86_OP_IMM, .size = 8, .imm = 0xdeadbeed },
		},
	},
	{
		// insn(X86_INS_MOV, X86_REG_RBX, 0xdeadbeee),
		.op_count = 2,
		.operands = {
			{ .type = X86_OP_REG, .size = 8, .reg = X86_REG_RBX },
			{ .type = X86_OP_IMM, .size = 8, .imm = 0xdeadbeee },
		},
	},
	{
		// insn(X86_INS_ADD, X86_REG_RBX, 1),
		.op_count = 2,
		.operands = {
			{ .type = X86_OP_REG, .size = 8, .reg = X86_REG_RBX },
			{ .type = X86_OP_IMM, .size = 8, .imm = 1 },
		},
	},
	{
		// insn(X86_INS_SUB, X86_REG_RAX, X86_REG_RBX),
		.op_count = 2,
		.operands = {
			{ .type = X86_OP_REG, .size = 8, .reg = X86_REG_RAX },
			{ .type = X86_OP_REG, .size = 8, .reg = X86_REG_RBX },
		},
	},
	{
		// insn(X86_INS_JLE, 2000),
		.op_count = 1,
		.operands = {
			{ .type = X86_OP_IMM, .size = 8, .imm = 2000 },
		},
	},
};

int main(int argc, const char** argv)
{
	x86_config config = { .ip = X86_REG_RIP, .sp = X86_REG_RSP, .fp = X86_REG_RBP };
	x86_regs regs = { .a.qword = static_cast<uint64_t>(argc), };
	
	regs.ip.qword++;
	x86_add_impl(&config, &operands[0], &regs);
	
	regs.ip.qword++;
	x86_mov_impl(&config, &operands[1], &regs);
	
	regs.ip.qword++;
	x86_add_impl(&config, &operands[2], &regs);
	
	regs.ip.qword++;
	x86_sub_impl(&config, &operands[3], &regs);
	
	regs.ip.qword++;
	x86_jle_impl(&config, &operands[4], &regs);
	
	printf("%llx\n", regs.ip.qword);
}
