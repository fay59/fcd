#include "x86_emulator.h"
#include <limits.h>

// /Users/felix/Projets/OpenSource/lldb/llvm/Release+Asserts/bin/clang++ --std=gnu++14 -stdlib=libc++ -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.10.sdk -I/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/include/c++/v1 -iquote /Users/felix/Projets/Reverse\ Kit/capstone/include -O3 -S -emit-llvm -o x86.ll x86_emulator.cpp

[[gnu::always_inline]]
static constexpr bool x86_clobber_bit()
{
	return false;
}

[[gnu::always_inline]]
static uint64_t x86_read_reg(const x86_regs* regs, x86_reg reg)
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

[[gnu::always_inline]]
static uint64_t x86_read_reg(const x86_regs* regs, const cs_x86_op* reg)
{
	return x86_read_reg(regs, reg->reg);
}

[[gnu::always_inline]]
static void x86_write_reg(x86_regs* regs, x86_reg reg, uint64_t value64)
{
	const x86_reg_info* reg_info = &x86_register_table[reg];
	const x86_reg_selector* selector = &reg_info->reg;
	uint64_t mask = ~0ull >> (64 - reg_info->size * CHAR_BIT);
	(regs->*selector->qword).qword = value64 & mask;
}

[[gnu::always_inline]]
static void x86_write_reg(x86_regs* regs, const cs_x86_op* reg, uint64_t value64)
{
	x86_write_reg(regs, reg->reg, value64);
}

[[gnu::always_inline]]
static uint64_t x86_get_effective_address(const x86_regs* regs, const cs_x86_op* op)
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

[[gnu::always_inline]]
static uint64_t x86_read_mem(const x86_regs* regs, const cs_x86_op* op)
{
	uint64_t address = x86_get_effective_address(regs, op);
	return x86_read_mem(address, op->size);
}

[[gnu::always_inline]]
static void x86_write_mem(const x86_regs* regs, const cs_x86_op* op, uint64_t value)
{
	uint64_t address = x86_get_effective_address(regs, op);
	x86_write_mem(address, op->size, value);
}

[[gnu::always_inline]]
static uint64_t x86_read_source_operand(const cs_x86_op* source, const x86_regs* regs)
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
			x86_assertion_failure("trying to read source from FP or invalid operand");
	}
}

[[gnu::always_inline]]
static uint64_t x86_read_destination_operand(const cs_x86_op* destination, const x86_regs* regs)
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
			x86_assertion_failure("trying to read destination from FP or invalid operand");
	}
}

[[gnu::always_inline]]
static void x86_write_destination_operand(const cs_x86_op* destination, x86_regs* regs, uint64_t value)
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

[[gnu::always_inline]]
static constexpr bool x86_add_and_adjust(uint64_t* accumulator)
{
	return false;
}

template<typename... TIntTypes>
[[gnu::always_inline]]
static bool x86_add_and_adjust(uint64_t* accumulator, uint64_t right, TIntTypes... rest)
{
	bool adjust = (*accumulator & 0xf) + (right & 0xf) > 0xf;
	*accumulator += right;
	return adjust | x86_add_and_adjust(accumulator, rest...);
}

[[gnu::always_inline]]
static constexpr bool x86_add_and_carry(uint64_t* accumulator)
{
	return false;
}

template<typename... TIntTypes>
[[gnu::always_inline]]
static bool x86_add_and_carry(uint64_t* accumulator, uint64_t right, TIntTypes... rest)
{
	bool carry = __builtin_uaddll_overflow(*accumulator, right, accumulator);
	return carry | x86_add_and_carry(accumulator, rest...);
}

template<typename... TIntTypes>
[[gnu::always_inline]]
static uint64_t x86_add_side_effects(x86_flags_reg* flags, size_t size, TIntTypes... ints)
{
	uint64_t result64 = 0;
	bool sign;
	bool carry = x86_add_and_carry(&result64, ints...);
	if (size == 1 || size == 2 || size == 4)
	{
		size_t cf_shift = size * CHAR_BIT;
		carry = (result64 >> cf_shift) & 1;
		sign = (result64 >> (cf_shift - 1)) & 1;
	}
	else if (size == 8)
	{
		sign = (result64 >> 63) & 1;
	}
	else
	{
		x86_assertion_failure("invalid destination size");
	}
	
	uint64_t adjust_acc = 0;
	flags->cf = carry;
	flags->sf = sign;
	flags->pf = __builtin_parityll(result64);
	flags->af = x86_add_and_adjust(&adjust_acc, ints...);
	flags->zf = result64 == 0;
	flags->of = flags->cf != flags->sf;
	return result64;
}

[[gnu::always_inline]]
static constexpr uint64_t x86_twos_complement(uint64_t input)
{
	return ~input + 1;
}

template<typename... TIntTypes>
[[gnu::always_inline]]
static uint64_t x86_subtract_side_effects(x86_flags_reg* output, size_t size, uint64_t left, TIntTypes... values)
{
	uint64_t result = x86_add_side_effects(output, size, left, x86_twos_complement(values)...);
	output->cf = !output->cf;
	output->af = !output->af;
	return result;
}

[[gnu::noreturn]]
extern "C" void x86_jump(const x86_config* config, x86_regs* __restrict__ regs, uint64_t location);

[[gnu::always_inline]]
static void x86_conditional_jump(const x86_config* __restrict__ config, x86_regs* __restrict__ regs, const cs_x86* inst, bool condition)
{
	if (condition)
	{
		uint64_t location = x86_read_source_operand(&inst->operands[0], regs);
		x86_jump(regs, location);
	}
}

template<typename TOperator>
[[gnu::always_inline]]
static uint64_t x86_logical_operator(x86_regs* regs, const cs_x86* inst, TOperator&& func)
{
	const cs_x86_op* source = &inst->operands[1];
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t right = x86_read_source_operand(source, regs);
	x86_flags_reg* flags = &regs->rflags;
	
	uint64_t result = func(left, right);
	flags->of = false;
	flags->cf = false;
	flags->sf = result >> (destination->size * CHAR_BIT - 1);
	flags->pf = __builtin_parityll(result);
	flags->zf = result == 0;
	flags->af = x86_clobber_bit();
	
	return result;
}

#pragma mark - Instruction Implementation
X86_INSTRUCTION_DEF(aaa)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(aad)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(aam)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(aas)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(adc)
{
	const cs_x86_op* source = &inst->operands[1];
	const cs_x86_op* destination = &inst->operands[0];
	x86_flags_reg* flags = &regs->rflags;
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t right = x86_read_source_operand(source, regs);
	uint64_t result = x86_add_side_effects(flags, destination->size, left, right, flags->cf);
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(adcx)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(add)
{
	const cs_x86_op* source = &inst->operands[1];
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t right = x86_read_source_operand(source, regs);
	uint64_t result = x86_add_side_effects(&regs->rflags, destination->size, left, right);
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(addpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(addps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(addsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(addss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(addsubpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(addsubps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(adox)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(aesdec)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(aesdeclast)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(aesenc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(aesenclast)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(aesimc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(aeskeygenassist)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(and)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t result = x86_logical_operator(regs, inst, [](uint64_t left, uint64_t right) { return left & right; });
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(andn)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(andnpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(andnps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(andpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(andps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(arpl)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(bextr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(blcfill)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(blci)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(blcic)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(blcmsk)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(blcs)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(blendpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(blendps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(blendvpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(blendvps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(blsfill)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(blsi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(blsic)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(blsmsk)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(blsr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(bound)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(bsf)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(bsr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(bswap)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(bt)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(btc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(btr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(bts)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(bzhi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(call)
{
	uint64_t target = x86_read_source_operand(&inst->operands[0], regs);
	x86_call_intrin(target, regs);
}

X86_INSTRUCTION_DEF(cbw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cdqe)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(clac)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(clc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cld)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(clflush)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(clgi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cli)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(clts)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmova)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmovae)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmovb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmovbe)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmove)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmovg)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmovge)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmovl)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmovle)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmovne)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmovno)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmovnp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmovns)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmovo)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmovp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmovs)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmp)
{
	const cs_x86_op* left = &inst->operands[0];
	const cs_x86_op* right = &inst->operands[1];
	uint64_t leftValue = x86_read_source_operand(left, regs);
	uint64_t rightValue = x86_read_source_operand(right, regs);
	x86_subtract_side_effects(&regs->rflags, left->size, leftValue, rightValue);
}

X86_INSTRUCTION_DEF(cmppd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmpps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmpsb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmpsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmpsq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmpss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmpsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmpxchg)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmpxchg16b)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cmpxchg8b)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(comisd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(comiss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cpuid)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cqo)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(crc32)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvtdq2pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvtdq2ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvtpd2dq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvtpd2pi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvtpd2ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvtpi2pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvtpi2ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvtps2dq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvtps2pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvtps2pi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvtsd2si)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvtsd2ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvtsi2sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvtsi2ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvtss2sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvtss2si)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvttpd2dq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvttpd2pi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvttps2dq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvttps2pi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvttsd2si)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cvttss2si)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cwd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(cwde)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(daa)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(das)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(data16)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(dec)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(div)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(divpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(divps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(divsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(divss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(dppd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(dpps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(emms)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(encls)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(enclu)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(enter)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(extractps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(extrq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(f2xm1)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fabs)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fadd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(faddp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fbld)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fbstp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fchs)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fcmovb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fcmovbe)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fcmove)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fcmovnb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fcmovnbe)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fcmovne)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fcmovnu)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fcmovu)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fcom)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fcomi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fcomp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fcompi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fcompp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fcos)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fdecstp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fdiv)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fdivp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fdivr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fdivrp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(femms)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(ffree)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fiadd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(ficom)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(ficomp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fidiv)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fidivr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fild)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fimul)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fincstp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fist)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fistp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fisttp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fisub)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fisubr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fld)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fld1)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fldcw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fldenv)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fldl2e)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fldl2t)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fldlg2)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fldln2)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fldpi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fldz)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fmul)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fmulp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fnclex)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fninit)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fnop)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fnsave)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fnstcw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fnstenv)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fnstsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fpatan)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fprem)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fprem1)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fptan)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(frndint)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(frstor)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fscale)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fsetpm)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fsin)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fsincos)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fsqrt)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fst)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fstp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fstpnce)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fsub)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fsubp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fsubr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fsubrp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(ftst)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fucom)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fucomi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fucomp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fucompi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fucompp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fxam)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fxch)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fxrstor)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fxrstor64)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fxsave)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fxsave64)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fxtract)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fyl2x)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(fyl2xp1)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(getsec)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(haddpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(haddps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(hlt)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(hsubpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(hsubps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(idiv)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(imul)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(in)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(inc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(insb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(insd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(insertps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(insertq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(insw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(int)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(int1)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(int3)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(into)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(invd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(invept)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(invlpg)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(invlpga)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(invpcid)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(invvpid)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(iret)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(iretd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(iretq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(ja)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(config, regs, inst, flags->cf == false && flags->zf == false);
}

X86_INSTRUCTION_DEF(jae)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(config, regs, inst, flags->cf == false);
}

X86_INSTRUCTION_DEF(jb)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(config, regs, inst, flags->cf == true);
}

X86_INSTRUCTION_DEF(jbe)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(config, regs, inst, flags->cf == true || flags->zf == true);
}

X86_INSTRUCTION_DEF(jcxz)
{
	x86_conditional_jump(config, regs, inst, x86_read_reg(regs, X86_REG_CX) == 0);
}

X86_INSTRUCTION_DEF(je)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(config, regs, inst, flags->zf == true);
}

X86_INSTRUCTION_DEF(jecxz)
{
	x86_conditional_jump(config, regs, inst, x86_read_reg(regs, X86_REG_ECX) == 0);
}

X86_INSTRUCTION_DEF(jg)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(config, regs, inst, flags->zf == false && flags->sf == flags->of);
}

X86_INSTRUCTION_DEF(jge)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(config, regs, inst, flags->sf == flags->of);
}

X86_INSTRUCTION_DEF(jl)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(config, regs, inst, flags->sf != flags->of);
}

X86_INSTRUCTION_DEF(jle)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(config, regs, inst, flags->zf == true || flags->sf != flags->of);
}

X86_INSTRUCTION_DEF(jmp)
{
	uint64_t location = x86_read_source_operand(&inst->operands[0], regs);
	x86_write_reg(regs, config->ip, location);
}

X86_INSTRUCTION_DEF(jne)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(config, regs, inst, flags->zf == false);
}

X86_INSTRUCTION_DEF(jno)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(config, regs, inst, flags->of == false);
}

X86_INSTRUCTION_DEF(jnp)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(config, regs, inst, flags->pf == false);
}

X86_INSTRUCTION_DEF(jns)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(config, regs, inst, flags->sf == false);
}

X86_INSTRUCTION_DEF(jo)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(config, regs, inst, flags->of == true);
}

X86_INSTRUCTION_DEF(jp)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(config, regs, inst, flags->pf == true);
}

X86_INSTRUCTION_DEF(jrcxz)
{
	x86_conditional_jump(config, regs, inst, x86_read_reg(regs, X86_REG_RCX) == 0);
}

X86_INSTRUCTION_DEF(js)
{
	x86_flags_reg* flags = &regs->rflags;
	x86_conditional_jump(config, regs, inst, flags->sf == true);
}

X86_INSTRUCTION_DEF(kandb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kandd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kandnb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kandnd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kandnq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kandnw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kandq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kandw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kmovb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kmovd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kmovq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kmovw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(knotb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(knotd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(knotq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(knotw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(korb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kord)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(korq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kortestw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(korw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kshiftlw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kshiftrw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kunpckbw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kxnorb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kxnord)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kxnorq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kxnorw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kxorb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kxord)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kxorq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(kxorw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lahf)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lar)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lcall)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lddqu)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(ldmxcsr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lds)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lea)
{
	const cs_x86_op* destination = &inst->operands[0];
	const cs_x86_op* source = &inst->operands[1];
	uint64_t value = x86_get_effective_address(regs, source);
	x86_write_destination_operand(destination, regs, value);
}

X86_INSTRUCTION_DEF(leave)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(les)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lfence)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lfs)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lgdt)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lgs)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lidt)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(ljmp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lldt)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lmsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lodsb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lodsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lodsq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lodsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(loop)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(loope)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(loopne)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lsl)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(ltr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(lzcnt)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(maskmovdqu)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(maskmovq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(maxpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(maxps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(maxsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(maxss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(mfence)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(minpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(minps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(minsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(minss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(monitor)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(montmul)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(mov)
{
	const cs_x86_op* source = &inst->operands[1];
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t writeValue = x86_read_source_operand(source, regs);
	x86_write_destination_operand(destination, regs, writeValue);
}

X86_INSTRUCTION_DEF(movabs)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movapd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movaps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movbe)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movddup)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movdq2q)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movdqa)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movdqu)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movhlps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movhpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movhps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movlhps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movlpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movlps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movmskpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movmskps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movntdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movntdqa)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movnti)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movntpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movntps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movntq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movntsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movntss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movq2dq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movsb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movshdup)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movsldup)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movsq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movsx)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movsxd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movupd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movups)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(movzx)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(mpsadbw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(mul)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(mulpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(mulps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(mulsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(mulss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(mulx)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(mwait)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(neg)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(nop)
{
	// do nothing
}

X86_INSTRUCTION_DEF(not)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(or)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t result = x86_logical_operator(regs, inst, [](uint64_t left, uint64_t right) { return left | right; });
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(orpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(orps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(out)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(outsb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(outsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(outsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pabsb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pabsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pabsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(packssdw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(packsswb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(packusdw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(packuswb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(paddb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(paddd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(paddq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(paddsb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(paddsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(paddusb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(paddusw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(paddw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(palignr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pand)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pandn)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pause)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pavgb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pavgusb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pavgw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pblendvb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pblendw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pclmulqdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pcmpeqb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pcmpeqd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pcmpeqq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pcmpeqw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pcmpestri)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pcmpestrm)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pcmpgtb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pcmpgtd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pcmpgtq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pcmpgtw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pcmpistri)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pcmpistrm)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pdep)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pext)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pextrb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pextrd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pextrq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pextrw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pf2id)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pf2iw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfacc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfadd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfcmpeq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfcmpge)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfcmpgt)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfmax)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfmin)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfmul)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfnacc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfpnacc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfrcp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfrcpit1)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfrcpit2)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfrsqit1)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfrsqrt)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfsub)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pfsubr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(phaddd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(phaddsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(phaddw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(phminposuw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(phsubd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(phsubsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(phsubw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pi2fd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pi2fw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pinsrb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pinsrd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pinsrq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pinsrw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmaddubsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmaddwd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmaxsb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmaxsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmaxsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmaxub)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmaxud)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmaxuw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pminsb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pminsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pminsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pminub)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pminud)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pminuw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmovmskb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmovsxbd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmovsxbq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmovsxbw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmovsxdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmovsxwd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmovsxwq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmovzxbd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmovzxbq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmovzxbw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmovzxdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmovzxwd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmovzxwq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmuldq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmulhrsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmulhrw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmulhuw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmulhw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmulld)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmullw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pmuludq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pop)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t pop_address = x86_read_reg(regs, config->sp);
	uint64_t popped = x86_read_mem(pop_address, destination->size);
	x86_write_reg(regs, config->sp, pop_address + destination->size);
	x86_write_destination_operand(destination, regs, popped);
}

X86_INSTRUCTION_DEF(popal)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(popaw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(popcnt)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(popf)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(popfd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(popfq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(por)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(prefetch)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(prefetchnta)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(prefetcht0)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(prefetcht1)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(prefetcht2)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(prefetchw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psadbw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pshufb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pshufd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pshufhw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pshuflw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pshufw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psignb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psignd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psignw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pslld)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pslldq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psllq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psllw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psrad)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psraw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psrld)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psrldq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psrlq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psrlw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psubb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psubd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psubq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psubsb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psubsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psubusb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psubusw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(psubw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pswapd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(ptest)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(punpckhbw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(punpckhdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(punpckhqdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(punpckhwd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(punpcklbw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(punpckldq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(punpcklqdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(punpcklwd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(push)
{
	const cs_x86_op* source = &inst->operands[0];
	uint64_t pushed = x86_read_source_operand(source, regs);
	uint64_t push_address = x86_read_reg(regs, config->sp) - source->size;
	x86_write_mem(push_address, source->size, pushed);
	x86_write_reg(regs, config->sp, push_address);
}

X86_INSTRUCTION_DEF(pushal)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pushaw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pushf)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pushfd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pushfq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(pxor)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rcl)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rcpps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rcpss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rcr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rdfsbase)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rdgsbase)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rdmsr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rdpmc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rdrand)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rdseed)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rdtsc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rdtscp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(ret)
{
	x86_ret_intrin(regs);
}

X86_INSTRUCTION_DEF(retf)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(retfq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rol)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(ror)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rorx)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(roundpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(roundps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(roundsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(roundss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rsm)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rsqrtps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(rsqrtss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sahf)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sal)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(salc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sar)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sarx)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sbb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(scasb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(scasd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(scasq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(scasw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(seta)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(setae)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(setb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(setbe)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sete)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(setg)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(setge)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(setl)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(setle)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(setne)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(setno)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(setnp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(setns)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(seto)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(setp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sets)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sfence)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sgdt)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sha1msg1)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sha1msg2)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sha1nexte)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sha1rnds4)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sha256msg1)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sha256msg2)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sha256rnds2)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(shl)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(shld)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(shlx)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(shr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(shrd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(shrx)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(shufpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(shufps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sidt)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(skinit)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sldt)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(smsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sqrtpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sqrtps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sqrtsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sqrtss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(stac)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(stc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(std)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(stgi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sti)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(stmxcsr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(stosb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(stosd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(stosq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(stosw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(str)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sub)
{
	const cs_x86_op* source = &inst->operands[1];
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t right = x86_read_source_operand(source, regs);
	uint64_t result = x86_subtract_side_effects(&regs->rflags, destination->size, left, right);
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(subpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(subps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(subsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(subss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(swapgs)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(syscall)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sysenter)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sysexit)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(sysret)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(t1mskc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(test)
{
	x86_logical_operator(regs, inst, [](uint64_t left, uint64_t right) { return left & right; });
}

X86_INSTRUCTION_DEF(tzcnt)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(tzmsk)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(ucomisd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(ucomiss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(ud2)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(ud2b)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(unpckhpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(unpckhps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(unpcklpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(unpcklps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vaddpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vaddps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vaddsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vaddss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vaddsubpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vaddsubps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vaesdec)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vaesdeclast)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vaesenc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vaesenclast)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vaesimc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vaeskeygenassist)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(valignd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(valignq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vandnpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vandnps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vandpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vandps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vblendmpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vblendmps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vblendpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vblendps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vblendvpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vblendvps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vbroadcastf128)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vbroadcasti128)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vbroadcasti32x4)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vbroadcasti64x4)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vbroadcastsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vbroadcastss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcmp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcmppd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcmpps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcmpsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcmpss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcomisd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcomiss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtdq2pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtdq2ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtpd2dq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtpd2dqx)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtpd2ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtpd2psx)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtpd2udq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtph2ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtps2dq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtps2pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtps2ph)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtps2udq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtsd2si)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtsd2ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtsd2usi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtsi2sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtsi2ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtss2sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtss2si)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtss2usi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvttpd2dq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvttpd2dqx)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvttpd2udq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvttps2dq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvttps2udq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvttsd2si)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvttsd2usi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvttss2si)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvttss2usi)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtudq2pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtudq2ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtusi2sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vcvtusi2ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vdivpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vdivps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vdivsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vdivss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vdppd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vdpps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(verr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(verw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vextractf128)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vextractf32x4)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vextractf64x4)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vextracti128)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vextracti32x4)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vextracti64x4)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vextractps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmadd132pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmadd132ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmadd132sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmadd132ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmadd213pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmadd213ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmadd213sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmadd213ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmadd231pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmadd231ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmadd231sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmadd231ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmaddpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmaddps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmaddsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmaddss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmaddsub132pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmaddsub132ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmaddsub213pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmaddsub213ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmaddsub231pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmaddsub231ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmaddsubpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmaddsubps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsub132pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsub132ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsub132sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsub132ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsub213pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsub213ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsub213sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsub213ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsub231pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsub231ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsub231sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsub231ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsubadd132pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsubadd132ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsubadd213pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsubadd213ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsubadd231pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsubadd231ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsubaddpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsubaddps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsubpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsubps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsubsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfmsubss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmadd132pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmadd132ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmadd132sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmadd132ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmadd213pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmadd213ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmadd213sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmadd213ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmadd231pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmadd231ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmadd231sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmadd231ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmaddpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmaddps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmaddsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmaddss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmsub132pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmsub132ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmsub132sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmsub132ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmsub213pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmsub213ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmsub213sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmsub213ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmsub231pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmsub231ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmsub231sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmsub231ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmsubpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmsubps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmsubsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfnmsubss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfrczpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfrczps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfrczsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vfrczss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vgatherdpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vgatherdps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vgatherpf0dpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vgatherpf0dps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vgatherpf0qpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vgatherpf0qps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vgatherpf1dpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vgatherpf1dps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vgatherpf1qpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vgatherpf1qps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vgatherqpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vgatherqps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vhaddpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vhaddps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vhsubpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vhsubps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vinsertf128)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vinsertf32x4)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vinsertf64x4)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vinserti128)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vinserti32x4)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vinserti64x4)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vinsertps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vlddqu)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vldmxcsr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmaskmovdqu)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmaskmovpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmaskmovps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmaxpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmaxps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmaxsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmaxss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmcall)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmclear)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmfunc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vminpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vminps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vminsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vminss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmlaunch)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmload)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmmcall)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovapd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovaps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovddup)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovdqa)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovdqa32)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovdqa64)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovdqu)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovdqu16)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovdqu32)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovdqu64)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovdqu8)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovhlps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovhpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovhps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovlhps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovlpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovlps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovmskpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovmskps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovntdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovntdqa)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovntpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovntps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovshdup)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovsldup)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovupd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmovups)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmpsadbw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmptrld)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmptrst)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmread)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmresume)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmrun)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmsave)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmulpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmulps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmulsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmulss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmwrite)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmxoff)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vmxon)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vorpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vorps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpabsb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpabsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpabsq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpabsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpackssdw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpacksswb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpackusdw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpackuswb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpaddb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpaddd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpaddq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpaddsb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpaddsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpaddusb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpaddusw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpaddw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpalignr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpand)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpandd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpandn)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpandnd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpandnq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpandq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpavgb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpavgw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpblendd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpblendmd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpblendmq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpblendvb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpblendw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpbroadcastb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpbroadcastd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpbroadcastmb2q)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpbroadcastmw2d)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpbroadcastq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpbroadcastw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpclmulqdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmov)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmp)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmpeqb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmpeqd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmpeqq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmpeqw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmpestri)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmpestrm)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmpgtb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmpgtd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmpgtq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmpgtw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmpistri)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmpistrm)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmpq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmpud)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcmpuq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcomb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcomd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcomq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcomub)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcomud)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcomuq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcomuw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpcomw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpconflictd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpconflictq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vperm2f128)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vperm2i128)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpermd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpermi2d)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpermi2pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpermi2ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpermi2q)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpermil2pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpermil2ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpermilpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpermilps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpermpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpermps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpermq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpermt2d)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpermt2pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpermt2ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpermt2q)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpextrb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpextrd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpextrq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpextrw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpgatherdd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpgatherdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpgatherqd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpgatherqq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphaddbd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphaddbq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphaddbw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphaddd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphadddq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphaddsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphaddubd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphaddubq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphaddubw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphaddudq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphadduwd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphadduwq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphaddw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphaddwd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphaddwq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphminposuw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphsubbw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphsubd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphsubdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphsubsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphsubw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vphsubwd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpinsrb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpinsrd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpinsrq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpinsrw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vplzcntd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vplzcntq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmacsdd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmacsdqh)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmacsdql)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmacssdd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmacssdqh)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmacssdql)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmacsswd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmacssww)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmacswd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmacsww)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmadcsswd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmadcswd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmaddubsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmaddwd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmaskmovd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmaskmovq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmaxsb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmaxsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmaxsq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmaxsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmaxub)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmaxud)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmaxuq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmaxuw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpminsb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpminsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpminsq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpminsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpminub)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpminud)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpminuq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpminuw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovdb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovdw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovmskb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovqb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovqd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovqw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovsdb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovsdw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovsqb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovsqd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovsqw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovsxbd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovsxbq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovsxbw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovsxdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovsxwd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovsxwq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovusdb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovusdw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovusqb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovusqd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovusqw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovzxbd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovzxbq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovzxbw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovzxdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovzxwd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmovzxwq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmuldq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmulhrsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmulhuw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmulhw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmulld)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmullw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpmuludq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpor)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpord)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vporq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpperm)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vprotb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vprotd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vprotq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vprotw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsadbw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpscatterdd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpscatterdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpscatterqd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpscatterqq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpshab)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpshad)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpshaq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpshaw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpshlb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpshld)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpshlq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpshlw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpshufb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpshufd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpshufhw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpshuflw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsignb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsignd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsignw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpslld)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpslldq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsllq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsllvd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsllvq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsllw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsrad)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsraq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsravd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsravq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsraw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsrld)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsrldq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsrlq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsrlvd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsrlvq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsrlw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsubb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsubd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsubq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsubsb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsubsw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsubusb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsubusw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpsubw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vptest)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vptestmd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vptestmq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vptestnmd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vptestnmq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpunpckhbw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpunpckhdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpunpckhqdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpunpckhwd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpunpcklbw)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpunpckldq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpunpcklqdq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpunpcklwd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpxor)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpxord)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vpxorq)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrcp14pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrcp14ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrcp14sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrcp14ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrcp28pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrcp28ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrcp28sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrcp28ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrcpps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrcpss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrndscalepd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrndscaleps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrndscalesd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrndscaless)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vroundpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vroundps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vroundsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vroundss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrsqrt14pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrsqrt14ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrsqrt14sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrsqrt14ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrsqrt28pd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrsqrt28ps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrsqrt28sd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrsqrt28ss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrsqrtps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vrsqrtss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vscatterdpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vscatterdps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vscatterpf0dpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vscatterpf0dps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vscatterpf0qpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vscatterpf0qps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vscatterpf1dpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vscatterpf1dps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vscatterpf1qpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vscatterpf1qps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vscatterqpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vscatterqps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vshufpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vshufps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vsqrtpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vsqrtps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vsqrtsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vsqrtss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vstmxcsr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vsubpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vsubps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vsubsd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vsubss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vtestpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vtestps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vucomisd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vucomiss)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vunpckhpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vunpckhps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vunpcklpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vunpcklps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vxorpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vxorps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vzeroall)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(vzeroupper)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(wait)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(wbinvd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(wrfsbase)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(wrgsbase)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(wrmsr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xabort)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xacquire)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xadd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xbegin)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xchg)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xcryptcbc)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xcryptcfb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xcryptctr)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xcryptecb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xcryptofb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xend)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xgetbv)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xlatb)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xor)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t result = x86_logical_operator(regs, inst, [](uint64_t left, uint64_t right) { return left ^ right; });
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(xorpd)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xorps)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xrelease)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xrstor)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xrstor64)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xsave)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xsave64)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xsaveopt)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xsaveopt64)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xsetbv)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xsha1)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xsha256)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xstore)
{
	x86_unimplemented(inst, regs);
}

X86_INSTRUCTION_DEF(xtest)
{
	x86_unimplemented(inst, regs);
}

#pragma mark - Register Table
const x86_reg_info x86_register_table[X86_REG_ENDING] = {
	[X86_REG_AH]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::a, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::high}},
	[X86_REG_AL]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::a, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::low}},
	[X86_REG_AX]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::a, &x86_qword_reg::low, &x86_dword_reg::low}},
	[X86_REG_BH]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::b, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::high}},
	[X86_REG_BL]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::b, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::low}},
	[X86_REG_BP]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::bp, &x86_qword_reg::low, &x86_dword_reg::low}},
	[X86_REG_BPL]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::bp, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::low}},
	[X86_REG_BX]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::b, &x86_qword_reg::low, &x86_dword_reg::low}},
	[X86_REG_CH]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::c, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::high}},
	[X86_REG_CL]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::c, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::low}},
	[X86_REG_CS]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::cs}},
	[X86_REG_CX]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::c, &x86_qword_reg::low, &x86_dword_reg::low}},
	[X86_REG_DH]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::d, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::high}},
	[X86_REG_DI]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::di, &x86_qword_reg::low, &x86_dword_reg::low}},
	[X86_REG_DIL]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::di, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::low}},
	[X86_REG_DL]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::d, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::low}},
	[X86_REG_DS]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::ds}},
	[X86_REG_DX]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::d, &x86_qword_reg::low, &x86_dword_reg::low}},
	[X86_REG_EAX]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::a, &x86_qword_reg::low}},
	[X86_REG_EBP]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::bp, &x86_qword_reg::low}},
	[X86_REG_EBX]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::b, &x86_qword_reg::low}},
	[X86_REG_ECX]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::c, &x86_qword_reg::low}},
	[X86_REG_EDI]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::di, &x86_qword_reg::low}},
	[X86_REG_EDX]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::d, &x86_qword_reg::low}},
	[X86_REG_EIP]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::ip, &x86_qword_reg::low}},
	[X86_REG_ES]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::es}},
	[X86_REG_ESI]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::si, &x86_qword_reg::low}},
	[X86_REG_ESP]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::sp, &x86_qword_reg::low}},
	[X86_REG_FS]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::fs}},
	[X86_REG_GS]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::gs}},
	[X86_REG_IP]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::ip, &x86_qword_reg::low, &x86_dword_reg::low}},
	[X86_REG_RAX]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::a}},
	[X86_REG_RBP]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::bp}},
	[X86_REG_RBX]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::b}},
	[X86_REG_RCX]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::c}},
	[X86_REG_RDI]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::di}},
	[X86_REG_RDX]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::d}},
	[X86_REG_RIP]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::ip}},
	[X86_REG_RSI]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::si}},
	[X86_REG_RSP]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::sp}},
	[X86_REG_SI]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::si, &x86_qword_reg::low, &x86_dword_reg::low}},
	[X86_REG_SIL]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::si, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::low}},
	[X86_REG_SP]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::sp, &x86_qword_reg::low, &x86_dword_reg::low}},
	[X86_REG_SPL]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::sp, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::low}},
	[X86_REG_SS]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::ss}},
	[X86_REG_K0]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::k0}},
	[X86_REG_K1]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::k1}},
	[X86_REG_K2]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::k2}},
	[X86_REG_K3]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::k3}},
	[X86_REG_K4]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::k4}},
	[X86_REG_K5]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::k5}},
	[X86_REG_K6]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::k6}},
	[X86_REG_K7]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::k7}},
	[X86_REG_R8]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::r8}},
	[X86_REG_R9]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::r9}},
	[X86_REG_R10]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::r10}},
	[X86_REG_R11]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::r11}},
	[X86_REG_R12]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::r12}},
	[X86_REG_R13]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::r13}},
	[X86_REG_R14]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::r14}},
	[X86_REG_R15]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::r15}},
	[X86_REG_R8B]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::r8, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::high}},
	[X86_REG_R9B]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::r9, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::high}},
	[X86_REG_R10B]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::r10, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::high}},
	[X86_REG_R11B]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::r11, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::high}},
	[X86_REG_R12B]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::r12, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::high}},
	[X86_REG_R13B]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::r13, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::high}},
	[X86_REG_R14B]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::r14, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::high}},
	[X86_REG_R15B]	= {.type = x86_reg_type::qword_reg,	.size = 1,	.reg = {&x86_regs::r15, &x86_qword_reg::low, &x86_dword_reg::low, &x86_word_reg::high}},
	[X86_REG_R8D]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::r8, &x86_qword_reg::low}},
	[X86_REG_R9D]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::r9, &x86_qword_reg::low}},
	[X86_REG_R10D]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::r10, &x86_qword_reg::low}},
	[X86_REG_R11D]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::r11, &x86_qword_reg::low}},
	[X86_REG_R12D]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::r12, &x86_qword_reg::low}},
	[X86_REG_R13D]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::r13, &x86_qword_reg::low}},
	[X86_REG_R14D]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::r14, &x86_qword_reg::low}},
	[X86_REG_R15D]	= {.type = x86_reg_type::qword_reg,	.size = 4,	.reg = {&x86_regs::r15, &x86_qword_reg::low}},
	[X86_REG_R8W]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::r8, &x86_qword_reg::low, &x86_dword_reg::low}},
	[X86_REG_R9W]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::r9, &x86_qword_reg::low, &x86_dword_reg::low}},
	[X86_REG_R10W]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::r10, &x86_qword_reg::low, &x86_dword_reg::low}},
	[X86_REG_R11W]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::r11, &x86_qword_reg::low, &x86_dword_reg::low}},
	[X86_REG_R12W]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::r12, &x86_qword_reg::low, &x86_dword_reg::low}},
	[X86_REG_R13W]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::r13, &x86_qword_reg::low, &x86_dword_reg::low}},
	[X86_REG_R14W]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::r14, &x86_qword_reg::low, &x86_dword_reg::low}},
	[X86_REG_R15W]	= {.type = x86_reg_type::qword_reg,	.size = 2,	.reg = {&x86_regs::r15, &x86_qword_reg::low, &x86_dword_reg::low}},
};
