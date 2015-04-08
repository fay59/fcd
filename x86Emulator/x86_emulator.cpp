#include "x86_emulator.h"
#include <limits.h>

// Most important instructions (covering ~93% of a program's code):
// √ mov
// √ nop
// √ add
// √ or
// √ call
// √ cmp
// √ lea
// √ jz
// √ sub
// √ xor
// √ test
// √ pop
// √ push
// √ jmp
// √ jnz
// x adc
// √ ret
// x outsd
// x and
// √ jb
// √ jo

static inline void clobber_reg(x86_reg reg, x86_regs* regs, const cs_x86_op* read_list, size_t read_list_count)
{
	const x86_reg_info* reg_info = &x86_register_table[reg];
	static_assert(static_cast<int>(x86_reg_type::enum_count) == 2, "");
	if (reg_info->type == x86_reg_type::qword_reg)
	{
		(regs->*reg_info->reg.qword) = x86_clobber_reg(read_list, read_list_count);
	}
	else if (reg_info->type == x86_reg_type::mm_reg)
	{
		(regs->*reg_info->mm) = x86_clobber_mmr(read_list, read_list_count);
	}
}

static inline constexpr bool x86_clobber_bit()
{
	return false;
}

static inline uint64_t x86_read_reg(const x86_regs* regs, x86_reg reg)
{
	const x86_reg_info* reg_info = &x86_register_table[reg];
	const x86_reg_selector* selector = &reg_info->reg;
	const x86_qword_reg* r64 = &(regs->*selector->qword);
	if (reg_info->size == 8)
	{
		return r64->qword;
	}
	
	const x86_dword_reg* r32 = &(r64->*selector->dword);
	if (reg_info->size == 4)
	{
		return r32->dword;
	}
	
	const x86_word_reg* r16 = &(r32->*selector->word);
	if (reg_info->size == 2)
	{
		return r16->word;
	}
	
	if (reg_info->size == 1)
	{
		uint8_t byte = r16->*selector->byte;
		return byte;
	}
	
	x86_assertion_failure("reading from register with non-standard size");
}

static inline uint64_t x86_read_reg(const x86_regs* regs, const cs_x86_op* reg)
{
	return x86_read_reg(regs, reg->reg);
}

static inline void x86_write_reg(x86_regs* regs, x86_reg reg, uint64_t value64)
{
	const x86_reg_info* reg_info = &x86_register_table[reg];
	const x86_reg_selector* selector = &reg_info->reg;
	uint64_t mask = (1ull << (reg_info->size * CHAR_BIT)) - 1;
	(regs->*selector->qword).qword = value64 & mask;
}

static inline void x86_write_reg(x86_regs* regs, const cs_x86_op* reg, uint64_t value64)
{
	x86_write_reg(regs, reg->reg, value64);
}

static inline uint64_t x86_get_effective_address(const x86_regs* regs, const cs_x86_op* op)
{
	uint64_t value = 0;
	const x86_op_mem* address = &op->mem;
	if (address->segment != X86_REG_INVALID)
	{
		value += x86_read_reg(regs, static_cast<x86_reg>(address->segment));
	}
	
	if (address->index != X86_REG_INVALID)
	{
		uint64_t index = x86_read_reg(regs, static_cast<x86_reg>(address->index));
		value += index * address->scale;
	}
	
	if (address->base != X86_REG_INVALID)
	{
		value += x86_read_reg(regs, static_cast<x86_reg>(address->base));
	}
	return value;
}

static inline uint64_t x86_read_mem(const x86_regs* regs, const cs_x86_op* op)
{
	uint64_t address = x86_get_effective_address(regs, op);
	return x86_read_mem(address, op->size);
}

static inline void x86_write_mem(const x86_regs* regs, const cs_x86_op* op, uint64_t value)
{
	uint64_t address = x86_get_effective_address(regs, op);
	x86_write_mem(address, op->size, value);
}

static inline uint64_t x86_read_source_operand(const cs_x86_op* source, const x86_regs* regs)
{
	switch (source->type)
	{
		case X86_OP_IMM:
			return static_cast<uint64_t>(source->imm);
			break;
			
		case X86_OP_REG:
			return x86_read_reg(regs, source);
			break;
			
		case X86_OP_MEM:
			return x86_read_mem(regs, source);
			break;
			
		default:
			x86_assertion_failure("mov trying to read from FP or invalid operand");
	}
}

static inline uint64_t x86_read_destination_operand(const cs_x86_op* destination, const x86_regs* regs)
{
	switch (destination->type)
	{
		case X86_OP_REG:
			return x86_read_reg(regs, destination);
			break;
			
		case X86_OP_MEM:
			return x86_read_mem(regs, destination);
			break;
			
		default:
			x86_assertion_failure("mov trying to read from FP or invalid operand");
	}
}

static inline void x86_write_destination_operand(const cs_x86_op* destination, x86_regs* regs, uint64_t value)
{
	switch (destination->type)
	{
		case X86_OP_REG:
			x86_write_reg(regs, destination, value);
			break;
			
		case X86_OP_MEM:
			x86_write_mem(regs, destination, value);
			break;
			
		default:
			x86_assertion_failure("mov trying to write to immediate, FP or invalid operand");
	}
}

static inline uint64_t x86_add_side_effects(size_t size, uint64_t left, uint64_t right, x86_flags_reg* flags)
{
	uint64_t result;
	if (size == 1)
	{
		uint16_t result16 = static_cast<uint16_t>(left + right);
		uint8_t result8 = result16 & 0xff;
		flags->cf = (result16 >> 8) & 1;
		flags->sf = result8 >> 7;
		result = result8;
	}
	else if (size == 2)
	{
		uint32_t result32 = static_cast<uint32_t>(left + right);
		uint16_t result16 = result32 & 0xffff;
		flags->cf = (result32 >> 16) & 1;
		flags->sf = result16 >> 15;
		result = result16;
	}
	else if (size == 4)
	{
		uint32_t result32;
		flags->cf = __builtin_uadd_overflow(static_cast<uint32_t>(left), static_cast<uint32_t>(right), &result32);
		flags->sf = result32 >> 31;
		result = result32;
	}
	else if (size == 8)
	{
		uint64_t result64;
		flags->cf = __builtin_uaddll_overflow(left, right, &result64);
		flags->sf = result64 >> 63;
	}
	else
	{
		x86_assertion_failure("invalid destination size");
	}
	
	flags->pf = __builtin_parityll(result);
	flags->af = (left & 0xf) + (right & 0xf) > 0xf;
	flags->zf = result == 0;
	flags->of = flags->cf != flags->sf;
	return result;
}

static inline uint64_t x86_subtract_side_effects(size_t size, uint64_t left, uint64_t right, x86_flags_reg* output)
{
	uint64_t rightTwosComplement = ~right + 1; // same as -right, but without UB on limit values
	uint64_t result = x86_add_side_effects(size, left, rightTwosComplement, output);
	output->cf = !output->cf;
	return result;
}

static inline void x86_conditional_jump(x86_regs* regs, const cs_insn* inst, bool condition)
{
	if (condition)
	{
		int64_t offset = inst->detail->x86.operands[0].imm;
		regs->ip.qword += offset;
	}
}

template<typename TOperator>
static inline uint64_t x86_binary_operator(x86_regs* regs, const cs_insn* inst, TOperator&& func)
{
	const cs_x86_op* source = &inst->detail->x86.operands[1];
	const cs_x86_op* destination = &inst->detail->x86.operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t right = x86_read_source_operand(source, regs);
	x86_flags_reg* flags = &regs->rflags;
	
	uint64_t result = func(left & right);
	flags->of = false;
	flags->cf = false;
	flags->sf = result >> (destination->size * CHAR_BIT - 1);
	flags->pf = __builtin_parityll(result);
	flags->zf = result == 0;
	flags->af = x86_clobber_bit();
	
	return result;
}

#pragma mark - Instruction Implementation
X86_INSTRUCTION(aaa)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(aad)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(aam)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(aas)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(adc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(adcx)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(add)
{
	const cs_x86_op* source = &inst->detail->x86.operands[1];
	const cs_x86_op* destination = &inst->detail->x86.operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t right = x86_read_source_operand(source, regs);
	uint64_t result = x86_add_side_effects(destination->size, left, right, &regs->rflags);
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION(addpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(addps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(addsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(addss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(addsubpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(addsubps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(adox)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(aesdec)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(aesdeclast)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(aesenc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(aesenclast)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(aesimc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(aeskeygenassist)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(and)
{
	const cs_x86_op* destination = &inst->detail->x86.operands[0];
	uint64_t result = x86_binary_operator(regs, inst, [](uint64_t left, uint64_t right) { return left & right; });
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION(andn)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(andnpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(andnps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(andpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(andps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(arpl)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(bextr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(blcfill)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(blci)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(blcic)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(blcmsk)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(blcs)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(blendpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(blendps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(blendvpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(blendvps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(blsfill)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(blsi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(blsic)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(blsmsk)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(blsr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(bound)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(bsf)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(bsr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(bswap)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(bt)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(btc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(btr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(bts)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(bzhi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(call)
{
	uint64_t target = x86_read_source_operand(&inst->detail->x86.operands[0], regs);
	x86_call_intrin(regs, target);
}

X86_INSTRUCTION(cbw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cdqe)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(clac)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(clc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cld)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(clflush)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(clgi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cli)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(clts)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmova)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmovae)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmovb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmovbe)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmove)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmovg)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmovge)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmovl)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmovle)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmovne)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmovno)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmovnp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmovns)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmovo)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmovp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmovs)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmp)
{
	const cs_x86_op* left = &inst->detail->x86.operands[0];
	const cs_x86_op* right = &inst->detail->x86.operands[1];
	uint64_t leftValue = x86_read_source_operand(left, regs);
	uint64_t rightValue = x86_read_source_operand(right, regs);
	x86_subtract_side_effects(left->size, leftValue, rightValue, &regs->rflags);
}

X86_INSTRUCTION(cmppd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmpps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmpsb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmpsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmpsq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmpss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmpsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmpxchg)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmpxchg16b)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cmpxchg8b)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(comisd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(comiss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cpuid)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cqo)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(crc32)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvtdq2pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvtdq2ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvtpd2dq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvtpd2pi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvtpd2ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvtpi2pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvtpi2ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvtps2dq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvtps2pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvtps2pi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvtsd2si)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvtsd2ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvtsi2sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvtsi2ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvtss2sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvtss2si)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvttpd2dq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvttpd2pi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvttps2dq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvttps2pi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvttsd2si)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cvttss2si)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cwd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(cwde)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(daa)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(das)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(data16)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(dec)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(div)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(divpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(divps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(divsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(divss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(dppd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(dpps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(emms)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(encls)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(enclu)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(enter)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(extractps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(extrq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(f2xm1)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fabs)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fadd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(faddp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fbld)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fbstp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fchs)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fcmovb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fcmovbe)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fcmove)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fcmovnb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fcmovnbe)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fcmovne)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fcmovnu)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fcmovu)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fcom)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fcomi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fcomp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fcompi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fcompp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fcos)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fdecstp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fdiv)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fdivp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fdivr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fdivrp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(femms)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(ffree)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fiadd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(ficom)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(ficomp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fidiv)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fidivr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fild)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fimul)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fincstp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fist)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fistp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fisttp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fisub)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fisubr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fld)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fld1)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fldcw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fldenv)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fldl2e)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fldl2t)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fldlg2)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fldln2)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fldpi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fldz)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fmul)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fmulp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fnclex)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fninit)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fnop)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fnsave)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fnstcw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fnstenv)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fnstsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fpatan)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fprem)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fprem1)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fptan)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(frndint)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(frstor)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fscale)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fsetpm)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fsin)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fsincos)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fsqrt)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fst)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fstp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fstpnce)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fsub)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fsubp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fsubr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fsubrp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(ftst)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fucom)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fucomi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fucomp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fucompi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fucompp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fxam)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fxch)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fxrstor)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fxrstor64)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fxsave)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fxsave64)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fxtract)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fyl2x)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(fyl2xp1)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(getsec)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(haddpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(haddps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(hlt)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(hsubpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(hsubps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(idiv)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(imul)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(in)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(inc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(insb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(insd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(insertps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(insertq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(insw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(int)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(int1)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(int3)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(into)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(invd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(invept)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(invlpg)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(invlpga)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(invpcid)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(invvpid)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(iret)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(iretd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(iretq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(ja)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(regs, inst, flags->cf == false && flags->zf == false);
}

X86_INSTRUCTION(jae)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(regs, inst, flags->cf == false);
}

X86_INSTRUCTION(jb)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(regs, inst, flags->cf == true);
}

X86_INSTRUCTION(jbe)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(regs, inst, flags->cf == true || flags->zf == true);
}

X86_INSTRUCTION(jcxz)
{
	x86_conditional_jump(regs, inst, x86_read_reg(regs, X86_REG_CX) == 0);
}

X86_INSTRUCTION(je)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(regs, inst, flags->zf == true);
}

X86_INSTRUCTION(jecxz)
{
	x86_conditional_jump(regs, inst, x86_read_reg(regs, X86_REG_ECX) == 0);
}

X86_INSTRUCTION(jg)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(regs, inst, flags->zf == false && flags->sf == flags->of);
}

X86_INSTRUCTION(jge)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(regs, inst, flags->sf == flags->of);
}

X86_INSTRUCTION(jl)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(regs, inst, flags->sf != flags->of);
}

X86_INSTRUCTION(jle)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(regs, inst, flags->zf == true || flags->sf != flags->of);
}

X86_INSTRUCTION(jmp)
{
	regs->ip.qword += x86_read_source_operand(&inst->detail->x86.operands[0], regs);
}

X86_INSTRUCTION(jne)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(regs, inst, flags->zf == false);
}

X86_INSTRUCTION(jno)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(regs, inst, flags->of == false);
}

X86_INSTRUCTION(jnp)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(regs, inst, flags->pf == false);
}

X86_INSTRUCTION(jns)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(regs, inst, flags->sf == false);
}

X86_INSTRUCTION(jo)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(regs, inst, flags->of == true);
}

X86_INSTRUCTION(jp)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(regs, inst, flags->pf == true);
}

X86_INSTRUCTION(jrcxz)
{
	x86_conditional_jump(regs, inst, x86_read_reg(regs, X86_REG_RCX) == 0);
}

X86_INSTRUCTION(js)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(regs, inst, flags->sf == true);
}

X86_INSTRUCTION(kandb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kandd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kandnb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kandnd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kandnq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kandnw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kandq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kandw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kmovb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kmovd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kmovq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kmovw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(knotb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(knotd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(knotq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(knotw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(korb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kord)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(korq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kortestw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(korw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kshiftlw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kshiftrw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kunpckbw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kxnorb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kxnord)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kxnorq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kxnorw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kxorb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kxord)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kxorq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(kxorw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lahf)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lar)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lcall)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lddqu)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(ldmxcsr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lds)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lea)
{
	const cs_x86_op* destination = &inst->detail->x86.operands[0];
	const cs_x86_op* source = &inst->detail->x86.operands[1];
	uint64_t value = x86_get_effective_address(regs, source);
	x86_write_destination_operand(destination, regs, value);
}

X86_INSTRUCTION(leave)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(les)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lfence)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lfs)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lgdt)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lgs)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lidt)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(ljmp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lldt)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lmsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lodsb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lodsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lodsq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lodsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(loop)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(loope)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(loopne)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lsl)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(ltr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(lzcnt)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(maskmovdqu)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(maskmovq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(maxpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(maxps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(maxsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(maxss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(mfence)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(minpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(minps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(minsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(minss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(monitor)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(montmul)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(mov)
{
	const cs_x86_op* source = &inst->detail->x86.operands[1];
	const cs_x86_op* destination = &inst->detail->x86.operands[0];
	uint64_t writeValue = x86_read_source_operand(source, regs);
	x86_write_destination_operand(destination, regs, writeValue);
}

X86_INSTRUCTION(movabs)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movapd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movaps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movbe)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movddup)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movdq2q)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movdqa)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movdqu)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movhlps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movhpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movhps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movlhps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movlpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movlps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movmskpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movmskps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movntdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movntdqa)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movnti)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movntpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movntps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movntq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movntsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movntss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movq2dq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movsb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movshdup)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movsldup)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movsq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movsx)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movsxd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movupd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movups)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(movzx)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(mpsadbw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(mul)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(mulpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(mulps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(mulsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(mulss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(mulx)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(mwait)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(neg)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(nop)
{
	// do nothing
}

X86_INSTRUCTION(not)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(or)
{
	const cs_x86_op* destination = &inst->detail->x86.operands[0];
	uint64_t result = x86_binary_operator(regs, inst, [](uint64_t left, uint64_t right) { return left | right; });
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION(orpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(orps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(out)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(outsb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(outsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(outsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pabsb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pabsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pabsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(packssdw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(packsswb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(packusdw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(packuswb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(paddb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(paddd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(paddq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(paddsb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(paddsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(paddusb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(paddusw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(paddw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(palignr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pand)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pandn)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pause)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pavgb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pavgusb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pavgw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pblendvb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pblendw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pclmulqdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pcmpeqb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pcmpeqd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pcmpeqq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pcmpeqw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pcmpestri)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pcmpestrm)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pcmpgtb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pcmpgtd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pcmpgtq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pcmpgtw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pcmpistri)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pcmpistrm)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pdep)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pext)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pextrb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pextrd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pextrq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pextrw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pf2id)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pf2iw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfacc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfadd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfcmpeq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfcmpge)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfcmpgt)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfmax)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfmin)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfmul)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfnacc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfpnacc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfrcp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfrcpit1)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfrcpit2)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfrsqit1)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfrsqrt)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfsub)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pfsubr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(phaddd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(phaddsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(phaddw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(phminposuw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(phsubd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(phsubsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(phsubw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pi2fd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pi2fw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pinsrb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pinsrd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pinsrq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pinsrw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmaddubsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmaddwd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmaxsb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmaxsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmaxsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmaxub)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmaxud)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmaxuw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pminsb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pminsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pminsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pminub)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pminud)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pminuw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmovmskb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmovsxbd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmovsxbq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmovsxbw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmovsxdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmovsxwd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmovsxwq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmovzxbd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmovzxbq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmovzxbw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmovzxdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmovzxwd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmovzxwq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmuldq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmulhrsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmulhrw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmulhuw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmulhw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmulld)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmullw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pmuludq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pop)
{
	const cs_x86_op* destination = &inst->detail->x86.operands[0];
	uint64_t pop_address = x86_read_reg(regs, config->sp);
	uint64_t popped = x86_read_mem(pop_address, destination->size);
	x86_write_reg(regs, config->sp, pop_address + destination->size);
	x86_write_destination_operand(destination, regs, popped);
}

X86_INSTRUCTION(popal)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(popaw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(popcnt)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(popf)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(popfd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(popfq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(por)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(prefetch)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(prefetchnta)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(prefetcht0)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(prefetcht1)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(prefetcht2)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(prefetchw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psadbw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pshufb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pshufd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pshufhw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pshuflw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pshufw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psignb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psignd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psignw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pslld)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pslldq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psllq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psllw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psrad)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psraw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psrld)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psrldq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psrlq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psrlw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psubb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psubd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psubq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psubsb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psubsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psubusb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psubusw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(psubw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pswapd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(ptest)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(punpckhbw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(punpckhdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(punpckhqdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(punpckhwd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(punpcklbw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(punpckldq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(punpcklqdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(punpcklwd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(push)
{
	const cs_x86_op* source = &inst->detail->x86.operands[0];
	uint64_t pushed = x86_read_source_operand(source, regs);
	uint64_t push_address = x86_read_reg(regs, config->sp) - source->size;
	x86_write_mem(push_address, source->size, pushed);
	x86_write_reg(regs, config->sp, push_address);
}

X86_INSTRUCTION(pushal)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pushaw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pushf)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pushfd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pushfq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(pxor)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rcl)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rcpps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rcpss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rcr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rdfsbase)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rdgsbase)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rdmsr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rdpmc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rdrand)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rdseed)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rdtsc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rdtscp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(ret)
{
	x86_ret_intrin();
}

X86_INSTRUCTION(retf)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(retfq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rol)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(ror)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rorx)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(roundpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(roundps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(roundsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(roundss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rsm)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rsqrtps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(rsqrtss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sahf)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sal)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(salc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sar)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sarx)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sbb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(scasb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(scasd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(scasq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(scasw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(seta)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(setae)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(setb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(setbe)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sete)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(setg)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(setge)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(setl)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(setle)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(setne)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(setno)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(setnp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(setns)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(seto)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(setp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sets)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sfence)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sgdt)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sha1msg1)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sha1msg2)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sha1nexte)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sha1rnds4)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sha256msg1)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sha256msg2)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sha256rnds2)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(shl)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(shld)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(shlx)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(shr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(shrd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(shrx)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(shufpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(shufps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sidt)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(skinit)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sldt)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(smsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sqrtpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sqrtps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sqrtsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sqrtss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(stac)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(stc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(std)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(stgi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sti)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(stmxcsr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(stosb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(stosd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(stosq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(stosw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(str)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sub)
{
	const cs_x86_op* source = &inst->detail->x86.operands[1];
	const cs_x86_op* destination = &inst->detail->x86.operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t right = x86_read_source_operand(source, regs);
	uint64_t result = x86_subtract_side_effects(destination->size, left, right, &regs->rflags);
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION(subpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(subps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(subsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(subss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(swapgs)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(syscall)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sysenter)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sysexit)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(sysret)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(t1mskc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(test)
{
	x86_binary_operator(regs, inst, [](uint64_t left, uint64_t right) { return left & right; });
}

X86_INSTRUCTION(tzcnt)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(tzmsk)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(ucomisd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(ucomiss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(ud2)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(ud2b)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(unpckhpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(unpckhps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(unpcklpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(unpcklps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vaddpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vaddps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vaddsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vaddss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vaddsubpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vaddsubps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vaesdec)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vaesdeclast)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vaesenc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vaesenclast)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vaesimc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vaeskeygenassist)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(valignd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(valignq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vandnpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vandnps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vandpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vandps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vblendmpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vblendmps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vblendpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vblendps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vblendvpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vblendvps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vbroadcastf128)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vbroadcasti128)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vbroadcasti32x4)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vbroadcasti64x4)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vbroadcastsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vbroadcastss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcmp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcmppd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcmpps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcmpsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcmpss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcomisd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcomiss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtdq2pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtdq2ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtpd2dq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtpd2dqx)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtpd2ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtpd2psx)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtpd2udq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtph2ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtps2dq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtps2pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtps2ph)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtps2udq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtsd2si)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtsd2ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtsd2usi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtsi2sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtsi2ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtss2sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtss2si)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtss2usi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvttpd2dq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvttpd2dqx)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvttpd2udq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvttps2dq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvttps2udq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvttsd2si)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvttsd2usi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvttss2si)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvttss2usi)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtudq2pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtudq2ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtusi2sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vcvtusi2ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vdivpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vdivps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vdivsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vdivss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vdppd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vdpps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(verr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(verw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vextractf128)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vextractf32x4)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vextractf64x4)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vextracti128)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vextracti32x4)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vextracti64x4)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vextractps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmadd132pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmadd132ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmadd132sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmadd132ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmadd213pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmadd213ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmadd213sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmadd213ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmadd231pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmadd231ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmadd231sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmadd231ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmaddpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmaddps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmaddsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmaddss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmaddsub132pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmaddsub132ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmaddsub213pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmaddsub213ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmaddsub231pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmaddsub231ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmaddsubpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmaddsubps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsub132pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsub132ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsub132sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsub132ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsub213pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsub213ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsub213sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsub213ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsub231pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsub231ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsub231sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsub231ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsubadd132pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsubadd132ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsubadd213pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsubadd213ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsubadd231pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsubadd231ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsubaddpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsubaddps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsubpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsubps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsubsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfmsubss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmadd132pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmadd132ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmadd132sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmadd132ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmadd213pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmadd213ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmadd213sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmadd213ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmadd231pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmadd231ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmadd231sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmadd231ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmaddpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmaddps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmaddsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmaddss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmsub132pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmsub132ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmsub132sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmsub132ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmsub213pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmsub213ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmsub213sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmsub213ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmsub231pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmsub231ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmsub231sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmsub231ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmsubpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmsubps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmsubsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfnmsubss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfrczpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfrczps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfrczsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vfrczss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vgatherdpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vgatherdps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vgatherpf0dpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vgatherpf0dps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vgatherpf0qpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vgatherpf0qps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vgatherpf1dpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vgatherpf1dps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vgatherpf1qpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vgatherpf1qps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vgatherqpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vgatherqps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vhaddpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vhaddps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vhsubpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vhsubps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vinsertf128)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vinsertf32x4)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vinsertf64x4)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vinserti128)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vinserti32x4)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vinserti64x4)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vinsertps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vlddqu)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vldmxcsr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmaskmovdqu)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmaskmovpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmaskmovps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmaxpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmaxps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmaxsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmaxss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmcall)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmclear)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmfunc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vminpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vminps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vminsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vminss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmlaunch)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmload)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmmcall)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovapd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovaps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovddup)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovdqa)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovdqa32)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovdqa64)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovdqu)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovdqu16)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovdqu32)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovdqu64)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovdqu8)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovhlps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovhpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovhps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovlhps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovlpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovlps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovmskpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovmskps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovntdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovntdqa)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovntpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovntps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovshdup)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovsldup)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovupd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmovups)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmpsadbw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmptrld)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmptrst)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmread)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmresume)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmrun)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmsave)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmulpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmulps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmulsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmulss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmwrite)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmxoff)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vmxon)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vorpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vorps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpabsb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpabsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpabsq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpabsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpackssdw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpacksswb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpackusdw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpackuswb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpaddb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpaddd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpaddq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpaddsb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpaddsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpaddusb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpaddusw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpaddw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpalignr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpand)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpandd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpandn)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpandnd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpandnq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpandq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpavgb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpavgw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpblendd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpblendmd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpblendmq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpblendvb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpblendw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpbroadcastb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpbroadcastd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpbroadcastmb2q)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpbroadcastmw2d)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpbroadcastq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpbroadcastw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpclmulqdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmov)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmp)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmpeqb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmpeqd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmpeqq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmpeqw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmpestri)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmpestrm)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmpgtb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmpgtd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmpgtq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmpgtw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmpistri)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmpistrm)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmpq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmpud)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcmpuq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcomb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcomd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcomq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcomub)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcomud)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcomuq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcomuw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpcomw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpconflictd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpconflictq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vperm2f128)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vperm2i128)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpermd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpermi2d)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpermi2pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpermi2ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpermi2q)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpermil2pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpermil2ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpermilpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpermilps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpermpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpermps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpermq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpermt2d)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpermt2pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpermt2ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpermt2q)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpextrb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpextrd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpextrq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpextrw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpgatherdd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpgatherdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpgatherqd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpgatherqq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphaddbd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphaddbq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphaddbw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphaddd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphadddq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphaddsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphaddubd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphaddubq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphaddubw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphaddudq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphadduwd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphadduwq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphaddw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphaddwd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphaddwq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphminposuw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphsubbw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphsubd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphsubdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphsubsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphsubw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vphsubwd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpinsrb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpinsrd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpinsrq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpinsrw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vplzcntd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vplzcntq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmacsdd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmacsdqh)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmacsdql)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmacssdd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmacssdqh)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmacssdql)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmacsswd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmacssww)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmacswd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmacsww)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmadcsswd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmadcswd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmaddubsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmaddwd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmaskmovd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmaskmovq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmaxsb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmaxsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmaxsq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmaxsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmaxub)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmaxud)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmaxuq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmaxuw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpminsb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpminsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpminsq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpminsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpminub)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpminud)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpminuq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpminuw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovdb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovdw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovmskb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovqb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovqd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovqw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovsdb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovsdw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovsqb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovsqd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovsqw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovsxbd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovsxbq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovsxbw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovsxdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovsxwd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovsxwq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovusdb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovusdw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovusqb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovusqd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovusqw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovzxbd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovzxbq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovzxbw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovzxdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovzxwd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmovzxwq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmuldq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmulhrsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmulhuw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmulhw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmulld)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmullw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpmuludq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpor)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpord)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vporq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpperm)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vprotb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vprotd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vprotq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vprotw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsadbw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpscatterdd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpscatterdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpscatterqd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpscatterqq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpshab)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpshad)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpshaq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpshaw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpshlb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpshld)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpshlq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpshlw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpshufb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpshufd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpshufhw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpshuflw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsignb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsignd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsignw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpslld)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpslldq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsllq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsllvd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsllvq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsllw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsrad)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsraq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsravd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsravq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsraw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsrld)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsrldq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsrlq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsrlvd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsrlvq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsrlw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsubb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsubd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsubq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsubsb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsubsw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsubusb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsubusw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpsubw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vptest)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vptestmd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vptestmq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vptestnmd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vptestnmq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpunpckhbw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpunpckhdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpunpckhqdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpunpckhwd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpunpcklbw)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpunpckldq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpunpcklqdq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpunpcklwd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpxor)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpxord)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vpxorq)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrcp14pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrcp14ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrcp14sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrcp14ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrcp28pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrcp28ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrcp28sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrcp28ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrcpps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrcpss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrndscalepd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrndscaleps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrndscalesd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrndscaless)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vroundpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vroundps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vroundsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vroundss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrsqrt14pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrsqrt14ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrsqrt14sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrsqrt14ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrsqrt28pd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrsqrt28ps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrsqrt28sd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrsqrt28ss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrsqrtps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vrsqrtss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vscatterdpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vscatterdps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vscatterpf0dpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vscatterpf0dps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vscatterpf0qpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vscatterpf0qps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vscatterpf1dpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vscatterpf1dps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vscatterpf1qpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vscatterpf1qps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vscatterqpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vscatterqps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vshufpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vshufps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vsqrtpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vsqrtps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vsqrtsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vsqrtss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vstmxcsr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vsubpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vsubps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vsubsd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vsubss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vtestpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vtestps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vucomisd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vucomiss)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vunpckhpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vunpckhps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vunpcklpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vunpcklps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vxorpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vxorps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vzeroall)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(vzeroupper)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(wait)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(wbinvd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(wrfsbase)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(wrgsbase)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(wrmsr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xabort)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xacquire)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xadd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xbegin)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xchg)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xcryptcbc)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xcryptcfb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xcryptctr)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xcryptecb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xcryptofb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xend)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xgetbv)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xlatb)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xor)
{
	const cs_x86_op* destination = &inst->detail->x86.operands[0];
	uint64_t result = x86_binary_operator(regs, inst, [](uint64_t left, uint64_t right) { return left & right; });
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION(xorpd)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xorps)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xrelease)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xrstor)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xrstor64)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xsave)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xsave64)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xsaveopt)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xsaveopt64)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xsetbv)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xsha1)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xsha256)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xstore)
{
	x86_unimplemented(regs, inst);
}

X86_INSTRUCTION(xtest)
{
	x86_unimplemented(regs, inst);
}
