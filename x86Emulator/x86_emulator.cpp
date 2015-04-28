#include "x86_emulator.h"
#include <cstring>
#include <limits.h>
#include <type_traits>

// /Users/felix/Projets/OpenSource/lldb/llvm/Release+Asserts/bin/clang++ --std=gnu++14 -stdlib=libc++ -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.10.sdk -I/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/include/c++/v1 -iquote /Users/felix/Projets/Reverse\ Kit/capstone/include -O3 -S -emit-llvm -o x86.ll x86_emulator.cpp

[[gnu::always_inline]]
static bool x86_parity(uint64_t value)
{
	return !__builtin_parity(static_cast<uint8_t>(value));
}

template<typename T>
[[gnu::always_inline]]
static int64_t make_signed(uint64_t value)
{
	static_assert(std::is_signed<T>::value, "type must be signed");
	return static_cast<T>(value);
}

[[gnu::always_inline]]
static uint64_t make_mask(size_t bits_set)
{
	return ~0ull >> (64 - bits_set);
}

[[gnu::always_inline]]
static bool x86_clobber_bit()
{
	bool b;
	return b;
}

[[gnu::always_inline]]
static uint64_t x86_read_reg(CPTR(x86_regs) regs, x86_reg reg)
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
static uint64_t x86_read_reg(CPTR(x86_regs) regs, CPTR(cs_x86_op) reg)
{
	return x86_read_reg(regs, reg->reg);
}

[[gnu::always_inline]]
static void x86_write_reg(PTR(x86_regs) regs, x86_reg reg, uint64_t value64)
{
	// 32-bit writes clear the upper bits of 64-bits registers;
	// 16-bit and 8-bit writes do not affect the rest of the register.
	const x86_reg_info* reg_info = &x86_register_table[reg];
	const x86_reg_selector* selector = &reg_info->reg;
	
	x86_qword_reg* r64 = &(regs->*selector->qword);
	if (reg_info->size == 8)
	{
		r64->qword = value64;
		return;
	}
	
	if (reg_info->size == 4)
	{
		// Clear whole register. Intentionally using r64 instead of r32.
		r64->qword = static_cast<uint32_t>(value64);
		return;
	}
	
	x86_dword_reg* r32 = &(r64->*selector->dword);
	x86_word_reg* r16 = &(r32->*selector->word);
	if (reg_info->size == 2)
	{
		r16->word = static_cast<uint16_t>(value64);
		return;
	}
	
	if (reg_info->size == 1)
	{
		r16->*selector->byte = static_cast<uint8_t>(value64);
		return;
	}
	
	x86_assertion_failure("writing to register with non-standard size");
}

[[gnu::always_inline]]
static void x86_write_reg(PTR(x86_regs) regs, CPTR(cs_x86_op) reg, uint64_t value64)
{
	x86_write_reg(regs, reg->reg, value64);
}

[[gnu::always_inline]]
static uint64_t x86_get_effective_address(CPTR(x86_regs) regs, CPTR(cs_x86_op) op)
{
	const x86_op_mem* address = &op->mem;
	uint64_t value = address->disp;
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
static uint64_t x86_read_mem(CPTR(x86_regs) regs, CPTR(cs_x86_op) op)
{
	uint64_t address = x86_get_effective_address(regs, op);
	return x86_read_mem(address, op->size);
}

[[gnu::always_inline]]
static void x86_write_mem(CPTR(x86_regs) regs, CPTR(cs_x86_op) op, uint64_t value)
{
	uint64_t address = x86_get_effective_address(regs, op);
	x86_write_mem(address, op->size, value);
}

[[gnu::always_inline]]
static uint64_t x86_read_source_operand(CPTR(cs_x86_op) source, CPTR(x86_regs) regs)
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
static uint64_t x86_read_destination_operand(CPTR(cs_x86_op) destination, CPTR(x86_regs) regs)
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
static void x86_write_destination_operand(CPTR(cs_x86_op) destination, PTR(x86_regs) regs, uint64_t value)
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
static uint64_t x86_add(PTR(x86_flags_reg) flags, size_t size, uint64_t a, uint64_t b)
{
	size_t bits_set = size * CHAR_BIT;
	uint64_t result;
	uint64_t sign_mask = make_mask(bits_set - 1);
	bool carry = __builtin_uaddll_overflow(a, b, &result);
	if (size == 1 || size == 2 || size == 4)
	{
		uint64_t mask = make_mask(bits_set);
		carry = result > mask;
		result &= mask;
	}
	else if (size != 8)
	{
		x86_assertion_failure("invalid destination size");
	}
	
	flags->cf |= carry;
	flags->af |= (a & 0xf) + (b & 0xf) > 0xf;
	flags->of |= ((result ^ a) & (result ^ b)) > sign_mask;
	flags->sf = result > sign_mask;
	flags->zf = result == 0;
	flags->pf = x86_parity(result);
	return result;
}

template<typename... TIntTypes>
[[gnu::always_inline]]
static uint64_t x86_subtract(PTR(x86_flags_reg) flags, size_t size, uint64_t left, uint64_t right)
{
	size_t bits_set = size * CHAR_BIT;
	uint64_t sign_mask = make_mask(bits_set - 1);
	uint64_t result;
	bool carry = __builtin_usubll_overflow(left, right, &result);
	if (size == 1 || size == 2 || size == 4)
	{
		uint64_t mask = make_mask(bits_set);
		carry = result > mask;
		result &= mask;
	}
	else if (size != 8)
	{
		x86_assertion_failure("invalid destination size");
	}
	
	flags->cf |= carry;
	flags->af |= (left & 0xf) - (right & 0xf) > 0xf;
	flags->of |= ((left ^ result) & (left ^ right)) > sign_mask;
	flags->sf = result > sign_mask;
	flags->zf = result == 0;
	flags->pf = x86_parity(result);
	return result;
}

template<typename TOperator>
[[gnu::always_inline]]
static uint64_t x86_logical_operator(PTR(x86_regs) regs, PTR(x86_flags_reg) rflags, CPTR(cs_x86) inst, TOperator&& func)
{
	const cs_x86_op* source = &inst->operands[1];
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t right = x86_read_source_operand(source, regs);
	x86_flags_reg* flags = rflags;
	
	uint64_t result = func(left, right);
	flags->of = false;
	flags->cf = false;
	flags->sf = result > make_mask(destination->size * CHAR_BIT - 1);
	flags->pf = x86_parity(result);
	flags->zf = result == 0;
	flags->af = x86_clobber_bit();
	
	return result;
}

[[gnu::always_inline]]
static void x86_push_value(CPTR(x86_config) config, PTR(x86_regs) regs, size_t size, uint64_t value)
{
	uint64_t push_address = x86_read_reg(regs, config->sp) - size;
	x86_write_mem(push_address, size, value);
	x86_write_reg(regs, config->sp, push_address);
}

[[gnu::always_inline]]
static uint64_t x86_pop_value(CPTR(x86_config) config, PTR(x86_regs) regs, size_t size)
{
	uint64_t pop_address = x86_read_reg(regs, config->sp);
	uint64_t popped = x86_read_mem(pop_address, size);
	x86_write_reg(regs, config->sp, pop_address + size);
	return popped;
}

[[gnu::always_inline]]
static void x86_move_zero_extend(PTR(x86_regs) regs, CPTR(cs_x86) inst)
{
	const cs_x86_op* source = &inst->operands[1];
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t writeValue = x86_read_source_operand(source, regs);
	x86_write_destination_operand(destination, regs, writeValue);
}

#pragma mark - Conditionals

[[gnu::always_inline]]
static bool x86_cond_above(CPTR(x86_flags_reg) flags)
{
	return flags->cf == false && flags->zf == false;
}

[[gnu::always_inline]]
static bool x86_cond_above_or_equal(CPTR(x86_flags_reg) flags)
{
	return flags->cf == false;
}

[[gnu::always_inline]]
static bool x86_cond_below(CPTR(x86_flags_reg) flags)
{
	return flags->cf == true;
}

[[gnu::always_inline]]
static bool x86_cond_below_or_equal(CPTR(x86_flags_reg) flags)
{
	return flags->cf == true || flags->zf == true;
}

[[gnu::always_inline]]
static bool x86_cond_equal(CPTR(x86_flags_reg) flags)
{
	return flags->zf == true;
}

[[gnu::always_inline]]
static bool x86_cond_greater(CPTR(x86_flags_reg) flags)
{
	return flags->zf == false && flags->sf == flags->of;
}

[[gnu::always_inline]]
static bool x86_cond_greater_or_equal(CPTR(x86_flags_reg) flags)
{
	return flags->sf == flags->of;
}

[[gnu::always_inline]]
static bool x86_cond_less(CPTR(x86_flags_reg) flags)
{
	return flags->sf != flags->of;
}

[[gnu::always_inline]]
static bool x86_cond_less_or_equal(CPTR(x86_flags_reg) flags)
{
	return flags->zf == true || flags->sf != flags->of;
}

[[gnu::always_inline]]
static bool x86_cond_not_equal(CPTR(x86_flags_reg) flags)
{
	return flags->zf == false;
}

[[gnu::always_inline]]
static bool x86_cond_no_overflow(CPTR(x86_flags_reg) flags)
{
	return flags->of == false;
}

[[gnu::always_inline]]
static bool x86_cond_no_parity(CPTR(x86_flags_reg) flags)
{
	return flags->pf == false;
}

[[gnu::always_inline]]
static bool x86_cond_no_sign(CPTR(x86_flags_reg) flags)
{
	return flags->sf == false;
}

[[gnu::always_inline]]
static bool x86_cond_overflow(CPTR(x86_flags_reg) flags)
{
	return flags->of == true;
}

[[gnu::always_inline]]
static bool x86_cond_parity(CPTR(x86_flags_reg) flags)
{
	return flags->pf == true;
}

[[gnu::always_inline]]
static bool x86_cond_signed(CPTR(x86_flags_reg) flags)
{
	return flags->sf == true;
}

[[gnu::always_inline]]
static void x86_conditional_jump(CPTR(x86_config) config, PTR(x86_regs) regs, CPTR(cs_x86) inst, bool condition)
{
	if (condition)
	{
		uint64_t location = x86_read_source_operand(&inst->operands[0], regs);
		x86_jump_intrin(config, regs, location);
	}
}

#pragma mark - Instruction Implementation
X86_INSTRUCTION_DEF(aaa)
{
	x86_unimplemented(regs, "aaa");
}

X86_INSTRUCTION_DEF(aad)
{
	x86_unimplemented(regs, "aad");
}

X86_INSTRUCTION_DEF(aam)
{
	x86_unimplemented(regs, "aam");
}

X86_INSTRUCTION_DEF(aas)
{
	x86_unimplemented(regs, "aas");
}

X86_INSTRUCTION_DEF(adc)
{
	const cs_x86_op* source = &inst->operands[1];
	const cs_x86_op* destination = &inst->operands[0];
	x86_flags_reg* flags = rflags;
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t right = x86_read_source_operand(source, regs);
	uint64_t result = rflags->cf;
	
	memset(rflags, 0, sizeof *rflags);
	result = x86_add(flags, source->size, result, left);
	result = x86_add(flags, source->size, result, right);
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(adcx)
{
	x86_unimplemented(regs, "adcx");
}

X86_INSTRUCTION_DEF(add)
{
	const cs_x86_op* source = &inst->operands[1];
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t right = x86_read_source_operand(source, regs);
	
	memset(rflags, 0, sizeof *rflags);
	uint64_t result = x86_add(rflags, source->size, left, right);
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(addpd)
{
	x86_unimplemented(regs, "addpd");
}

X86_INSTRUCTION_DEF(addps)
{
	x86_unimplemented(regs, "addps");
}

X86_INSTRUCTION_DEF(addsd)
{
	x86_unimplemented(regs, "addsd");
}

X86_INSTRUCTION_DEF(addss)
{
	x86_unimplemented(regs, "addss");
}

X86_INSTRUCTION_DEF(addsubpd)
{
	x86_unimplemented(regs, "addsubpd");
}

X86_INSTRUCTION_DEF(addsubps)
{
	x86_unimplemented(regs, "addsubps");
}

X86_INSTRUCTION_DEF(adox)
{
	x86_unimplemented(regs, "adox");
}

X86_INSTRUCTION_DEF(aesdec)
{
	x86_unimplemented(regs, "aesdec");
}

X86_INSTRUCTION_DEF(aesdeclast)
{
	x86_unimplemented(regs, "aesdeclast");
}

X86_INSTRUCTION_DEF(aesenc)
{
	x86_unimplemented(regs, "aesenc");
}

X86_INSTRUCTION_DEF(aesenclast)
{
	x86_unimplemented(regs, "aesenclast");
}

X86_INSTRUCTION_DEF(aesimc)
{
	x86_unimplemented(regs, "aesimc");
}

X86_INSTRUCTION_DEF(aeskeygenassist)
{
	x86_unimplemented(regs, "aeskeygenassist");
}

X86_INSTRUCTION_DEF(and)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t result = x86_logical_operator(regs, rflags, inst, [](uint64_t left, uint64_t right) { return left & right; });
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(andn)
{
	x86_unimplemented(regs, "andn");
}

X86_INSTRUCTION_DEF(andnpd)
{
	x86_unimplemented(regs, "andnpd");
}

X86_INSTRUCTION_DEF(andnps)
{
	x86_unimplemented(regs, "andnps");
}

X86_INSTRUCTION_DEF(andpd)
{
	x86_unimplemented(regs, "andpd");
}

X86_INSTRUCTION_DEF(andps)
{
	x86_unimplemented(regs, "andps");
}

X86_INSTRUCTION_DEF(arpl)
{
	x86_unimplemented(regs, "arpl");
}

X86_INSTRUCTION_DEF(bextr)
{
	x86_unimplemented(regs, "bextr");
}

X86_INSTRUCTION_DEF(blcfill)
{
	x86_unimplemented(regs, "blcfill");
}

X86_INSTRUCTION_DEF(blci)
{
	x86_unimplemented(regs, "blci");
}

X86_INSTRUCTION_DEF(blcic)
{
	x86_unimplemented(regs, "blcic");
}

X86_INSTRUCTION_DEF(blcmsk)
{
	x86_unimplemented(regs, "blcmsk");
}

X86_INSTRUCTION_DEF(blcs)
{
	x86_unimplemented(regs, "blcs");
}

X86_INSTRUCTION_DEF(blendpd)
{
	x86_unimplemented(regs, "blendpd");
}

X86_INSTRUCTION_DEF(blendps)
{
	x86_unimplemented(regs, "blendps");
}

X86_INSTRUCTION_DEF(blendvpd)
{
	x86_unimplemented(regs, "blendvpd");
}

X86_INSTRUCTION_DEF(blendvps)
{
	x86_unimplemented(regs, "blendvps");
}

X86_INSTRUCTION_DEF(blsfill)
{
	x86_unimplemented(regs, "blsfill");
}

X86_INSTRUCTION_DEF(blsi)
{
	x86_unimplemented(regs, "blsi");
}

X86_INSTRUCTION_DEF(blsic)
{
	x86_unimplemented(regs, "blsic");
}

X86_INSTRUCTION_DEF(blsmsk)
{
	x86_unimplemented(regs, "blsmsk");
}

X86_INSTRUCTION_DEF(blsr)
{
	x86_unimplemented(regs, "blsr");
}

X86_INSTRUCTION_DEF(bound)
{
	x86_unimplemented(regs, "bound");
}

X86_INSTRUCTION_DEF(bsf)
{
	x86_unimplemented(regs, "bsf");
}

X86_INSTRUCTION_DEF(bsr)
{
	x86_unimplemented(regs, "bsr");
}

X86_INSTRUCTION_DEF(bswap)
{
	x86_unimplemented(regs, "bswap");
}

X86_INSTRUCTION_DEF(bt)
{
	x86_unimplemented(regs, "bt");
}

X86_INSTRUCTION_DEF(btc)
{
	x86_unimplemented(regs, "btc");
}

X86_INSTRUCTION_DEF(btr)
{
	x86_unimplemented(regs, "btr");
}

X86_INSTRUCTION_DEF(bts)
{
	x86_unimplemented(regs, "bts");
}

X86_INSTRUCTION_DEF(bzhi)
{
	x86_unimplemented(regs, "bzhi");
}

X86_INSTRUCTION_DEF(call)
{
	uint64_t target = x86_read_source_operand(&inst->operands[0], regs);
	x86_call_intrin(config, regs, target);
}

X86_INSTRUCTION_DEF(cbw)
{
	x86_unimplemented(regs, "cbw");
}

X86_INSTRUCTION_DEF(cdq)
{
	x86_unimplemented(regs, "cdq");
}

X86_INSTRUCTION_DEF(cdqe)
{
	x86_unimplemented(regs, "cdqe");
}

X86_INSTRUCTION_DEF(clac)
{
	x86_unimplemented(regs, "clac");
}

X86_INSTRUCTION_DEF(clc)
{
	x86_unimplemented(regs, "clc");
}

X86_INSTRUCTION_DEF(cld)
{
	x86_unimplemented(regs, "cld");
}

X86_INSTRUCTION_DEF(clflush)
{
	x86_unimplemented(regs, "clflush");
}

X86_INSTRUCTION_DEF(clgi)
{
	x86_unimplemented(regs, "clgi");
}

X86_INSTRUCTION_DEF(cli)
{
	x86_unimplemented(regs, "cli");
}

X86_INSTRUCTION_DEF(clts)
{
	x86_unimplemented(regs, "clts");
}

X86_INSTRUCTION_DEF(cmc)
{
	x86_unimplemented(regs, "cmc");
}

X86_INSTRUCTION_DEF(cmova)
{
	if (x86_cond_above(rflags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovae)
{
	if (x86_cond_above_or_equal(rflags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovb)
{
	if (x86_cond_below(rflags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovbe)
{
	if (x86_cond_below_or_equal(rflags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmove)
{
	if (x86_cond_equal(rflags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovg)
{
	if (x86_cond_greater(rflags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovge)
{
	if (x86_cond_greater_or_equal(rflags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovl)
{
	if (x86_cond_less(rflags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovle)
{
	if (x86_cond_less_or_equal(rflags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovne)
{
	if (x86_cond_not_equal(rflags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovno)
{
	if (x86_cond_no_overflow(rflags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovnp)
{
	if (x86_cond_no_parity(rflags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovns)
{
	if (x86_cond_no_sign(rflags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovo)
{
	if (x86_cond_overflow(rflags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovp)
{
	if (x86_cond_parity(rflags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovs)
{
	if (x86_cond_signed(rflags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmp)
{
	const cs_x86_op* left = &inst->operands[0];
	const cs_x86_op* right = &inst->operands[1];
	uint64_t leftValue = x86_read_source_operand(left, regs);
	uint64_t rightValue = x86_read_source_operand(right, regs);
	
	memset(rflags, 0, sizeof *rflags);
	x86_subtract(rflags, left->size, leftValue, rightValue);
}

X86_INSTRUCTION_DEF(cmppd)
{
	x86_unimplemented(regs, "cmppd");
}

X86_INSTRUCTION_DEF(cmpps)
{
	x86_unimplemented(regs, "cmpps");
}

X86_INSTRUCTION_DEF(cmpsb)
{
	x86_unimplemented(regs, "cmpsb");
}

X86_INSTRUCTION_DEF(cmpsd)
{
	x86_unimplemented(regs, "cmpsd");
}

X86_INSTRUCTION_DEF(cmpsq)
{
	x86_unimplemented(regs, "cmpsq");
}

X86_INSTRUCTION_DEF(cmpss)
{
	x86_unimplemented(regs, "cmpss");
}

X86_INSTRUCTION_DEF(cmpsw)
{
	x86_unimplemented(regs, "cmpsw");
}

X86_INSTRUCTION_DEF(cmpxchg)
{
	x86_unimplemented(regs, "cmpxchg");
}

X86_INSTRUCTION_DEF(cmpxchg16b)
{
	x86_unimplemented(regs, "cmpxchg16b");
}

X86_INSTRUCTION_DEF(cmpxchg8b)
{
	x86_unimplemented(regs, "cmpxchg8b");
}

X86_INSTRUCTION_DEF(comisd)
{
	x86_unimplemented(regs, "comisd");
}

X86_INSTRUCTION_DEF(comiss)
{
	x86_unimplemented(regs, "comiss");
}

X86_INSTRUCTION_DEF(cpuid)
{
	x86_unimplemented(regs, "cpuid");
}

X86_INSTRUCTION_DEF(cqo)
{
	x86_unimplemented(regs, "cqo");
}

X86_INSTRUCTION_DEF(crc32)
{
	x86_unimplemented(regs, "crc32");
}

X86_INSTRUCTION_DEF(cvtdq2pd)
{
	x86_unimplemented(regs, "cvtdq2pd");
}

X86_INSTRUCTION_DEF(cvtdq2ps)
{
	x86_unimplemented(regs, "cvtdq2ps");
}

X86_INSTRUCTION_DEF(cvtpd2dq)
{
	x86_unimplemented(regs, "cvtpd2dq");
}

X86_INSTRUCTION_DEF(cvtpd2pi)
{
	x86_unimplemented(regs, "cvtpd2pi");
}

X86_INSTRUCTION_DEF(cvtpd2ps)
{
	x86_unimplemented(regs, "cvtpd2ps");
}

X86_INSTRUCTION_DEF(cvtpi2pd)
{
	x86_unimplemented(regs, "cvtpi2pd");
}

X86_INSTRUCTION_DEF(cvtpi2ps)
{
	x86_unimplemented(regs, "cvtpi2ps");
}

X86_INSTRUCTION_DEF(cvtps2dq)
{
	x86_unimplemented(regs, "cvtps2dq");
}

X86_INSTRUCTION_DEF(cvtps2pd)
{
	x86_unimplemented(regs, "cvtps2pd");
}

X86_INSTRUCTION_DEF(cvtps2pi)
{
	x86_unimplemented(regs, "cvtps2pi");
}

X86_INSTRUCTION_DEF(cvtsd2si)
{
	x86_unimplemented(regs, "cvtsd2si");
}

X86_INSTRUCTION_DEF(cvtsd2ss)
{
	x86_unimplemented(regs, "cvtsd2ss");
}

X86_INSTRUCTION_DEF(cvtsi2sd)
{
	x86_unimplemented(regs, "cvtsi2sd");
}

X86_INSTRUCTION_DEF(cvtsi2ss)
{
	x86_unimplemented(regs, "cvtsi2ss");
}

X86_INSTRUCTION_DEF(cvtss2sd)
{
	x86_unimplemented(regs, "cvtss2sd");
}

X86_INSTRUCTION_DEF(cvtss2si)
{
	x86_unimplemented(regs, "cvtss2si");
}

X86_INSTRUCTION_DEF(cvttpd2dq)
{
	x86_unimplemented(regs, "cvttpd2dq");
}

X86_INSTRUCTION_DEF(cvttpd2pi)
{
	x86_unimplemented(regs, "cvttpd2pi");
}

X86_INSTRUCTION_DEF(cvttps2dq)
{
	x86_unimplemented(regs, "cvttps2dq");
}

X86_INSTRUCTION_DEF(cvttps2pi)
{
	x86_unimplemented(regs, "cvttps2pi");
}

X86_INSTRUCTION_DEF(cvttsd2si)
{
	x86_unimplemented(regs, "cvttsd2si");
}

X86_INSTRUCTION_DEF(cvttss2si)
{
	x86_unimplemented(regs, "cvttss2si");
}

X86_INSTRUCTION_DEF(cwd)
{
	x86_unimplemented(regs, "cwd");
}

X86_INSTRUCTION_DEF(cwde)
{
	x86_unimplemented(regs, "cwde");
}

X86_INSTRUCTION_DEF(daa)
{
	x86_unimplemented(regs, "daa");
}

X86_INSTRUCTION_DEF(das)
{
	x86_unimplemented(regs, "das");
}

X86_INSTRUCTION_DEF(data16)
{
	x86_unimplemented(regs, "data16");
}

X86_INSTRUCTION_DEF(dec)
{
	x86_unimplemented(regs, "dec");
}

X86_INSTRUCTION_DEF(div)
{
	x86_unimplemented(regs, "div");
}

X86_INSTRUCTION_DEF(divpd)
{
	x86_unimplemented(regs, "divpd");
}

X86_INSTRUCTION_DEF(divps)
{
	x86_unimplemented(regs, "divps");
}

X86_INSTRUCTION_DEF(divsd)
{
	x86_unimplemented(regs, "divsd");
}

X86_INSTRUCTION_DEF(divss)
{
	x86_unimplemented(regs, "divss");
}

X86_INSTRUCTION_DEF(dppd)
{
	x86_unimplemented(regs, "dppd");
}

X86_INSTRUCTION_DEF(dpps)
{
	x86_unimplemented(regs, "dpps");
}

X86_INSTRUCTION_DEF(emms)
{
	x86_unimplemented(regs, "emms");
}

X86_INSTRUCTION_DEF(encls)
{
	x86_unimplemented(regs, "encls");
}

X86_INSTRUCTION_DEF(enclu)
{
	x86_unimplemented(regs, "enclu");
}

X86_INSTRUCTION_DEF(enter)
{
	x86_unimplemented(regs, "enter");
}

X86_INSTRUCTION_DEF(extractps)
{
	x86_unimplemented(regs, "extractps");
}

X86_INSTRUCTION_DEF(extrq)
{
	x86_unimplemented(regs, "extrq");
}

X86_INSTRUCTION_DEF(f2xm1)
{
	x86_unimplemented(regs, "f2xm1");
}

X86_INSTRUCTION_DEF(fabs)
{
	x86_unimplemented(regs, "fabs");
}

X86_INSTRUCTION_DEF(fadd)
{
	x86_unimplemented(regs, "fadd");
}

X86_INSTRUCTION_DEF(faddp)
{
	x86_unimplemented(regs, "faddp");
}

X86_INSTRUCTION_DEF(fbld)
{
	x86_unimplemented(regs, "fbld");
}

X86_INSTRUCTION_DEF(fbstp)
{
	x86_unimplemented(regs, "fbstp");
}

X86_INSTRUCTION_DEF(fchs)
{
	x86_unimplemented(regs, "fchs");
}

X86_INSTRUCTION_DEF(fcmovb)
{
	x86_unimplemented(regs, "fcmovb");
}

X86_INSTRUCTION_DEF(fcmovbe)
{
	x86_unimplemented(regs, "fcmovbe");
}

X86_INSTRUCTION_DEF(fcmove)
{
	x86_unimplemented(regs, "fcmove");
}

X86_INSTRUCTION_DEF(fcmovnb)
{
	x86_unimplemented(regs, "fcmovnb");
}

X86_INSTRUCTION_DEF(fcmovnbe)
{
	x86_unimplemented(regs, "fcmovnbe");
}

X86_INSTRUCTION_DEF(fcmovne)
{
	x86_unimplemented(regs, "fcmovne");
}

X86_INSTRUCTION_DEF(fcmovnu)
{
	x86_unimplemented(regs, "fcmovnu");
}

X86_INSTRUCTION_DEF(fcmovu)
{
	x86_unimplemented(regs, "fcmovu");
}

X86_INSTRUCTION_DEF(fcom)
{
	x86_unimplemented(regs, "fcom");
}

X86_INSTRUCTION_DEF(fcomi)
{
	x86_unimplemented(regs, "fcomi");
}

X86_INSTRUCTION_DEF(fcomp)
{
	x86_unimplemented(regs, "fcomp");
}

X86_INSTRUCTION_DEF(fcompi)
{
	x86_unimplemented(regs, "fcompi");
}

X86_INSTRUCTION_DEF(fcompp)
{
	x86_unimplemented(regs, "fcompp");
}

X86_INSTRUCTION_DEF(fcos)
{
	x86_unimplemented(regs, "fcos");
}

X86_INSTRUCTION_DEF(fdecstp)
{
	x86_unimplemented(regs, "fdecstp");
}

X86_INSTRUCTION_DEF(fdiv)
{
	x86_unimplemented(regs, "fdiv");
}

X86_INSTRUCTION_DEF(fdivp)
{
	x86_unimplemented(regs, "fdivp");
}

X86_INSTRUCTION_DEF(fdivr)
{
	x86_unimplemented(regs, "fdivr");
}

X86_INSTRUCTION_DEF(fdivrp)
{
	x86_unimplemented(regs, "fdivrp");
}

X86_INSTRUCTION_DEF(femms)
{
	x86_unimplemented(regs, "femms");
}

X86_INSTRUCTION_DEF(ffree)
{
	x86_unimplemented(regs, "ffree");
}

X86_INSTRUCTION_DEF(fiadd)
{
	x86_unimplemented(regs, "fiadd");
}

X86_INSTRUCTION_DEF(ficom)
{
	x86_unimplemented(regs, "ficom");
}

X86_INSTRUCTION_DEF(ficomp)
{
	x86_unimplemented(regs, "ficomp");
}

X86_INSTRUCTION_DEF(fidiv)
{
	x86_unimplemented(regs, "fidiv");
}

X86_INSTRUCTION_DEF(fidivr)
{
	x86_unimplemented(regs, "fidivr");
}

X86_INSTRUCTION_DEF(fild)
{
	x86_unimplemented(regs, "fild");
}

X86_INSTRUCTION_DEF(fimul)
{
	x86_unimplemented(regs, "fimul");
}

X86_INSTRUCTION_DEF(fincstp)
{
	x86_unimplemented(regs, "fincstp");
}

X86_INSTRUCTION_DEF(fist)
{
	x86_unimplemented(regs, "fist");
}

X86_INSTRUCTION_DEF(fistp)
{
	x86_unimplemented(regs, "fistp");
}

X86_INSTRUCTION_DEF(fisttp)
{
	x86_unimplemented(regs, "fisttp");
}

X86_INSTRUCTION_DEF(fisub)
{
	x86_unimplemented(regs, "fisub");
}

X86_INSTRUCTION_DEF(fisubr)
{
	x86_unimplemented(regs, "fisubr");
}

X86_INSTRUCTION_DEF(fld)
{
	x86_unimplemented(regs, "fld");
}

X86_INSTRUCTION_DEF(fld1)
{
	x86_unimplemented(regs, "fld1");
}

X86_INSTRUCTION_DEF(fldcw)
{
	x86_unimplemented(regs, "fldcw");
}

X86_INSTRUCTION_DEF(fldenv)
{
	x86_unimplemented(regs, "fldenv");
}

X86_INSTRUCTION_DEF(fldl2e)
{
	x86_unimplemented(regs, "fldl2e");
}

X86_INSTRUCTION_DEF(fldl2t)
{
	x86_unimplemented(regs, "fldl2t");
}

X86_INSTRUCTION_DEF(fldlg2)
{
	x86_unimplemented(regs, "fldlg2");
}

X86_INSTRUCTION_DEF(fldln2)
{
	x86_unimplemented(regs, "fldln2");
}

X86_INSTRUCTION_DEF(fldpi)
{
	x86_unimplemented(regs, "fldpi");
}

X86_INSTRUCTION_DEF(fldz)
{
	x86_unimplemented(regs, "fldz");
}

X86_INSTRUCTION_DEF(fmul)
{
	x86_unimplemented(regs, "fmul");
}

X86_INSTRUCTION_DEF(fmulp)
{
	x86_unimplemented(regs, "fmulp");
}

X86_INSTRUCTION_DEF(fnclex)
{
	x86_unimplemented(regs, "fnclex");
}

X86_INSTRUCTION_DEF(fninit)
{
	x86_unimplemented(regs, "fninit");
}

X86_INSTRUCTION_DEF(fnop)
{
	x86_unimplemented(regs, "fnop");
}

X86_INSTRUCTION_DEF(fnsave)
{
	x86_unimplemented(regs, "fnsave");
}

X86_INSTRUCTION_DEF(fnstcw)
{
	x86_unimplemented(regs, "fnstcw");
}

X86_INSTRUCTION_DEF(fnstenv)
{
	x86_unimplemented(regs, "fnstenv");
}

X86_INSTRUCTION_DEF(fnstsw)
{
	x86_unimplemented(regs, "fnstsw");
}

X86_INSTRUCTION_DEF(fpatan)
{
	x86_unimplemented(regs, "fpatan");
}

X86_INSTRUCTION_DEF(fprem)
{
	x86_unimplemented(regs, "fprem");
}

X86_INSTRUCTION_DEF(fprem1)
{
	x86_unimplemented(regs, "fprem1");
}

X86_INSTRUCTION_DEF(fptan)
{
	x86_unimplemented(regs, "fptan");
}

X86_INSTRUCTION_DEF(frndint)
{
	x86_unimplemented(regs, "frndint");
}

X86_INSTRUCTION_DEF(frstor)
{
	x86_unimplemented(regs, "frstor");
}

X86_INSTRUCTION_DEF(fscale)
{
	x86_unimplemented(regs, "fscale");
}

X86_INSTRUCTION_DEF(fsetpm)
{
	x86_unimplemented(regs, "fsetpm");
}

X86_INSTRUCTION_DEF(fsin)
{
	x86_unimplemented(regs, "fsin");
}

X86_INSTRUCTION_DEF(fsincos)
{
	x86_unimplemented(regs, "fsincos");
}

X86_INSTRUCTION_DEF(fsqrt)
{
	x86_unimplemented(regs, "fsqrt");
}

X86_INSTRUCTION_DEF(fst)
{
	x86_unimplemented(regs, "fst");
}

X86_INSTRUCTION_DEF(fstp)
{
	x86_unimplemented(regs, "fstp");
}

X86_INSTRUCTION_DEF(fstpnce)
{
	x86_unimplemented(regs, "fstpnce");
}

X86_INSTRUCTION_DEF(fsub)
{
	x86_unimplemented(regs, "fsub");
}

X86_INSTRUCTION_DEF(fsubp)
{
	x86_unimplemented(regs, "fsubp");
}

X86_INSTRUCTION_DEF(fsubr)
{
	x86_unimplemented(regs, "fsubr");
}

X86_INSTRUCTION_DEF(fsubrp)
{
	x86_unimplemented(regs, "fsubrp");
}

X86_INSTRUCTION_DEF(ftst)
{
	x86_unimplemented(regs, "ftst");
}

X86_INSTRUCTION_DEF(fucom)
{
	x86_unimplemented(regs, "fucom");
}

X86_INSTRUCTION_DEF(fucomi)
{
	x86_unimplemented(regs, "fucomi");
}

X86_INSTRUCTION_DEF(fucomp)
{
	x86_unimplemented(regs, "fucomp");
}

X86_INSTRUCTION_DEF(fucompi)
{
	x86_unimplemented(regs, "fucompi");
}

X86_INSTRUCTION_DEF(fucompp)
{
	x86_unimplemented(regs, "fucompp");
}

X86_INSTRUCTION_DEF(fxam)
{
	x86_unimplemented(regs, "fxam");
}

X86_INSTRUCTION_DEF(fxch)
{
	x86_unimplemented(regs, "fxch");
}

X86_INSTRUCTION_DEF(fxrstor)
{
	x86_unimplemented(regs, "fxrstor");
}

X86_INSTRUCTION_DEF(fxrstor64)
{
	x86_unimplemented(regs, "fxrstor64");
}

X86_INSTRUCTION_DEF(fxsave)
{
	x86_unimplemented(regs, "fxsave");
}

X86_INSTRUCTION_DEF(fxsave64)
{
	x86_unimplemented(regs, "fxsave64");
}

X86_INSTRUCTION_DEF(fxtract)
{
	x86_unimplemented(regs, "fxtract");
}

X86_INSTRUCTION_DEF(fyl2x)
{
	x86_unimplemented(regs, "fyl2x");
}

X86_INSTRUCTION_DEF(fyl2xp1)
{
	x86_unimplemented(regs, "fyl2xp1");
}

X86_INSTRUCTION_DEF(getsec)
{
	x86_unimplemented(regs, "getsec");
}

X86_INSTRUCTION_DEF(haddpd)
{
	x86_unimplemented(regs, "haddpd");
}

X86_INSTRUCTION_DEF(haddps)
{
	x86_unimplemented(regs, "haddps");
}

X86_INSTRUCTION_DEF(hlt)
{
	x86_unimplemented(regs, "hlt");
}

X86_INSTRUCTION_DEF(hsubpd)
{
	x86_unimplemented(regs, "hsubpd");
}

X86_INSTRUCTION_DEF(hsubps)
{
	x86_unimplemented(regs, "hsubps");
}

X86_INSTRUCTION_DEF(idiv)
{
	x86_unimplemented(regs, "idiv");
}

X86_INSTRUCTION_DEF(imul)
{
	// imul has 3 variations:
	// - imul r/m
	// - imul r, r/m
	// - imul r, r/m, imm
	// The first form can't be precisely expressed in C because it stores its result in two registers. The upside is
	// that it shouldn't naturally find its way into compiled C programs.
	
	// SF had undefined contents up until relatively recently. Set it, but don't check it with tests
	// (the implementation is trivial anyway).
	
	int64_t left, right;
	const cs_x86_op* destination = &inst->operands[0];
	switch (inst->op_count)
	{
		case 2:
			left = x86_read_destination_operand(destination, regs);
			right = x86_read_source_operand(&inst->operands[1], regs);
			break;
			
		case 3:
			left = x86_read_source_operand(&inst->operands[1], regs);
			right = x86_read_source_operand(&inst->operands[2], regs);
			break;
			
		default: x86_assertion_failure("single-operand imul form is not implemented");
	}
	
	int64_t result;
	switch (destination->size)
	{
		case 1:
		{
			using result_type = int8_t;
			left = make_signed<result_type>(left);
			right = make_signed<result_type>(right);
			result = left * right;
			auto truncated = static_cast<result_type>(result);
			rflags->cf = rflags->of = truncated != result;
			rflags->sf = truncated < 0;
			break;
		}
			
		case 2:
		{
			using result_type = int16_t;
			left = make_signed<result_type>(left);
			right = make_signed<result_type>(right);
			result = left * right;
			auto truncated = static_cast<result_type>(result);
			rflags->cf = rflags->of = truncated != result;
			rflags->sf = truncated < 0;
			break;
		}
			
		case 4:
		{
			using result_type = int32_t;
			left = make_signed<result_type>(left);
			right = make_signed<result_type>(right);
			result = left * right;
			auto truncated = static_cast<result_type>(result);
			rflags->cf = rflags->of = truncated != result;
			rflags->sf = truncated < 0;
			break;
		}
			
		case 8:
		{
			rflags->cf = rflags->of = __builtin_smulll_overflow(left, right, &result);
			rflags->sf = result < 0;
			break;
		}
			
		default: x86_assertion_failure("unexpected multiply size");
	}
	
	rflags->af = x86_clobber_bit();
	rflags->pf = x86_clobber_bit();
	rflags->zf = x86_clobber_bit();
	x86_write_destination_operand(destination, regs, result); // will be truncated down the pipeline
}

X86_INSTRUCTION_DEF(in)
{
	x86_unimplemented(regs, "in");
}

X86_INSTRUCTION_DEF(inc)
{
	x86_unimplemented(regs, "inc");
}

X86_INSTRUCTION_DEF(insb)
{
	x86_unimplemented(regs, "insb");
}

X86_INSTRUCTION_DEF(insd)
{
	x86_unimplemented(regs, "insd");
}

X86_INSTRUCTION_DEF(insertps)
{
	x86_unimplemented(regs, "insertps");
}

X86_INSTRUCTION_DEF(insertq)
{
	x86_unimplemented(regs, "insertq");
}

X86_INSTRUCTION_DEF(insw)
{
	x86_unimplemented(regs, "insw");
}

X86_INSTRUCTION_DEF(int)
{
	x86_unimplemented(regs, "int");
}

X86_INSTRUCTION_DEF(int1)
{
	x86_unimplemented(regs, "int1");
}

X86_INSTRUCTION_DEF(int3)
{
	x86_unimplemented(regs, "int3");
}

X86_INSTRUCTION_DEF(into)
{
	x86_unimplemented(regs, "into");
}

X86_INSTRUCTION_DEF(invd)
{
	x86_unimplemented(regs, "invd");
}

X86_INSTRUCTION_DEF(invept)
{
	x86_unimplemented(regs, "invept");
}

X86_INSTRUCTION_DEF(invlpg)
{
	x86_unimplemented(regs, "invlpg");
}

X86_INSTRUCTION_DEF(invlpga)
{
	x86_unimplemented(regs, "invlpga");
}

X86_INSTRUCTION_DEF(invpcid)
{
	x86_unimplemented(regs, "invpcid");
}

X86_INSTRUCTION_DEF(invvpid)
{
	x86_unimplemented(regs, "invvpid");
}

X86_INSTRUCTION_DEF(iret)
{
	x86_unimplemented(regs, "iret");
}

X86_INSTRUCTION_DEF(iretd)
{
	x86_unimplemented(regs, "iretd");
}

X86_INSTRUCTION_DEF(iretq)
{
	x86_unimplemented(regs, "iretq");
}

X86_INSTRUCTION_DEF(ja)
{
	x86_flags_reg* flags = rflags;
	x86_conditional_jump(config, regs, inst, x86_cond_above(flags));
}

X86_INSTRUCTION_DEF(jae)
{
	x86_flags_reg* flags = rflags;
	x86_conditional_jump(config, regs, inst, x86_cond_above_or_equal(flags));
}

X86_INSTRUCTION_DEF(jb)
{
	x86_flags_reg* flags = rflags;
	x86_conditional_jump(config, regs, inst, x86_cond_below(flags));
}

X86_INSTRUCTION_DEF(jbe)
{
	x86_flags_reg* flags = rflags;
	x86_conditional_jump(config, regs, inst, x86_cond_below_or_equal(flags));
}

X86_INSTRUCTION_DEF(jcxz)
{
	x86_conditional_jump(config, regs, inst, x86_read_reg(regs, X86_REG_CX) == 0);
}

X86_INSTRUCTION_DEF(je)
{
	x86_flags_reg* flags = rflags;
	x86_conditional_jump(config, regs, inst, x86_cond_equal(flags));
}

X86_INSTRUCTION_DEF(jecxz)
{
	x86_conditional_jump(config, regs, inst, x86_read_reg(regs, X86_REG_ECX) == 0);
}

X86_INSTRUCTION_DEF(jg)
{
	x86_flags_reg* flags = rflags;
	x86_conditional_jump(config, regs, inst, x86_cond_greater(flags));
}

X86_INSTRUCTION_DEF(jge)
{
	x86_flags_reg* flags = rflags;
	x86_conditional_jump(config, regs, inst, x86_cond_greater_or_equal(flags));
}

X86_INSTRUCTION_DEF(jl)
{
	x86_flags_reg* flags = rflags;
	x86_conditional_jump(config, regs, inst, x86_cond_less(flags));
}

X86_INSTRUCTION_DEF(jle)
{
	x86_flags_reg* flags = rflags;
	x86_conditional_jump(config, regs, inst, x86_cond_less_or_equal(flags));
}

X86_INSTRUCTION_DEF(jmp)
{
	uint64_t location = x86_read_source_operand(&inst->operands[0], regs);
	x86_jump_intrin(config, regs, location);
}

X86_INSTRUCTION_DEF(jne)
{
	x86_flags_reg* flags = rflags;
	x86_conditional_jump(config, regs, inst, x86_cond_not_equal(flags));
}

X86_INSTRUCTION_DEF(jno)
{
	x86_flags_reg* flags = rflags;
	x86_conditional_jump(config, regs, inst, x86_cond_no_overflow(flags));
}

X86_INSTRUCTION_DEF(jnp)
{
	x86_flags_reg* flags = rflags;
	x86_conditional_jump(config, regs, inst, x86_cond_no_parity(flags));
}

X86_INSTRUCTION_DEF(jns)
{
	x86_flags_reg* flags = rflags;
	x86_conditional_jump(config, regs, inst, x86_cond_no_sign(flags));
}

X86_INSTRUCTION_DEF(jo)
{
	x86_flags_reg* flags = rflags;
	x86_conditional_jump(config, regs, inst, x86_cond_overflow(flags));
}

X86_INSTRUCTION_DEF(jp)
{
	x86_flags_reg* flags = rflags;
	x86_conditional_jump(config, regs, inst, x86_cond_parity(flags));
}

X86_INSTRUCTION_DEF(jrcxz)
{
	x86_conditional_jump(config, regs, inst, x86_read_reg(regs, X86_REG_RCX) == 0);
}

X86_INSTRUCTION_DEF(js)
{
	x86_flags_reg* flags = rflags;
	x86_conditional_jump(config, regs, inst, x86_cond_signed(flags));
}

X86_INSTRUCTION_DEF(kandb)
{
	x86_unimplemented(regs, "kandb");
}

X86_INSTRUCTION_DEF(kandd)
{
	x86_unimplemented(regs, "kandd");
}

X86_INSTRUCTION_DEF(kandnb)
{
	x86_unimplemented(regs, "kandnb");
}

X86_INSTRUCTION_DEF(kandnd)
{
	x86_unimplemented(regs, "kandnd");
}

X86_INSTRUCTION_DEF(kandnq)
{
	x86_unimplemented(regs, "kandnq");
}

X86_INSTRUCTION_DEF(kandnw)
{
	x86_unimplemented(regs, "kandnw");
}

X86_INSTRUCTION_DEF(kandq)
{
	x86_unimplemented(regs, "kandq");
}

X86_INSTRUCTION_DEF(kandw)
{
	x86_unimplemented(regs, "kandw");
}

X86_INSTRUCTION_DEF(kmovb)
{
	x86_unimplemented(regs, "kmovb");
}

X86_INSTRUCTION_DEF(kmovd)
{
	x86_unimplemented(regs, "kmovd");
}

X86_INSTRUCTION_DEF(kmovq)
{
	x86_unimplemented(regs, "kmovq");
}

X86_INSTRUCTION_DEF(kmovw)
{
	x86_unimplemented(regs, "kmovw");
}

X86_INSTRUCTION_DEF(knotb)
{
	x86_unimplemented(regs, "knotb");
}

X86_INSTRUCTION_DEF(knotd)
{
	x86_unimplemented(regs, "knotd");
}

X86_INSTRUCTION_DEF(knotq)
{
	x86_unimplemented(regs, "knotq");
}

X86_INSTRUCTION_DEF(knotw)
{
	x86_unimplemented(regs, "knotw");
}

X86_INSTRUCTION_DEF(korb)
{
	x86_unimplemented(regs, "korb");
}

X86_INSTRUCTION_DEF(kord)
{
	x86_unimplemented(regs, "kord");
}

X86_INSTRUCTION_DEF(korq)
{
	x86_unimplemented(regs, "korq");
}

X86_INSTRUCTION_DEF(kortestw)
{
	x86_unimplemented(regs, "kortestw");
}

X86_INSTRUCTION_DEF(korw)
{
	x86_unimplemented(regs, "korw");
}

X86_INSTRUCTION_DEF(kshiftlw)
{
	x86_unimplemented(regs, "kshiftlw");
}

X86_INSTRUCTION_DEF(kshiftrw)
{
	x86_unimplemented(regs, "kshiftrw");
}

X86_INSTRUCTION_DEF(kunpckbw)
{
	x86_unimplemented(regs, "kunpckbw");
}

X86_INSTRUCTION_DEF(kxnorb)
{
	x86_unimplemented(regs, "kxnorb");
}

X86_INSTRUCTION_DEF(kxnord)
{
	x86_unimplemented(regs, "kxnord");
}

X86_INSTRUCTION_DEF(kxnorq)
{
	x86_unimplemented(regs, "kxnorq");
}

X86_INSTRUCTION_DEF(kxnorw)
{
	x86_unimplemented(regs, "kxnorw");
}

X86_INSTRUCTION_DEF(kxorb)
{
	x86_unimplemented(regs, "kxorb");
}

X86_INSTRUCTION_DEF(kxord)
{
	x86_unimplemented(regs, "kxord");
}

X86_INSTRUCTION_DEF(kxorq)
{
	x86_unimplemented(regs, "kxorq");
}

X86_INSTRUCTION_DEF(kxorw)
{
	x86_unimplemented(regs, "kxorw");
}

X86_INSTRUCTION_DEF(lahf)
{
	x86_unimplemented(regs, "lahf");
}

X86_INSTRUCTION_DEF(lar)
{
	x86_unimplemented(regs, "lar");
}

X86_INSTRUCTION_DEF(lcall)
{
	x86_unimplemented(regs, "lcall");
}

X86_INSTRUCTION_DEF(lddqu)
{
	x86_unimplemented(regs, "lddqu");
}

X86_INSTRUCTION_DEF(ldmxcsr)
{
	x86_unimplemented(regs, "ldmxcsr");
}

X86_INSTRUCTION_DEF(lds)
{
	x86_unimplemented(regs, "lds");
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
	regs->sp = regs->bp;
	regs->bp.qword = x86_pop_value(config, regs, config->address_size / 8);
}

X86_INSTRUCTION_DEF(les)
{
	x86_unimplemented(regs, "les");
}

X86_INSTRUCTION_DEF(lfence)
{
	x86_unimplemented(regs, "lfence");
}

X86_INSTRUCTION_DEF(lfs)
{
	x86_unimplemented(regs, "lfs");
}

X86_INSTRUCTION_DEF(lgdt)
{
	x86_unimplemented(regs, "lgdt");
}

X86_INSTRUCTION_DEF(lgs)
{
	x86_unimplemented(regs, "lgs");
}

X86_INSTRUCTION_DEF(lidt)
{
	x86_unimplemented(regs, "lidt");
}

X86_INSTRUCTION_DEF(ljmp)
{
	x86_unimplemented(regs, "ljmp");
}

X86_INSTRUCTION_DEF(lldt)
{
	x86_unimplemented(regs, "lldt");
}

X86_INSTRUCTION_DEF(lmsw)
{
	x86_unimplemented(regs, "lmsw");
}

X86_INSTRUCTION_DEF(lodsb)
{
	x86_unimplemented(regs, "lodsb");
}

X86_INSTRUCTION_DEF(lodsd)
{
	x86_unimplemented(regs, "lodsd");
}

X86_INSTRUCTION_DEF(lodsq)
{
	x86_unimplemented(regs, "lodsq");
}

X86_INSTRUCTION_DEF(lodsw)
{
	x86_unimplemented(regs, "lodsw");
}

X86_INSTRUCTION_DEF(loop)
{
	x86_unimplemented(regs, "loop");
}

X86_INSTRUCTION_DEF(loope)
{
	x86_unimplemented(regs, "loope");
}

X86_INSTRUCTION_DEF(loopne)
{
	x86_unimplemented(regs, "loopne");
}

X86_INSTRUCTION_DEF(lsl)
{
	x86_unimplemented(regs, "lsl");
}

X86_INSTRUCTION_DEF(lss)
{
	x86_unimplemented(regs, "lss");
}

X86_INSTRUCTION_DEF(ltr)
{
	x86_unimplemented(regs, "ltr");
}

X86_INSTRUCTION_DEF(lzcnt)
{
	x86_unimplemented(regs, "lzcnt");
}

X86_INSTRUCTION_DEF(maskmovdqu)
{
	x86_unimplemented(regs, "maskmovdqu");
}

X86_INSTRUCTION_DEF(maskmovq)
{
	x86_unimplemented(regs, "maskmovq");
}

X86_INSTRUCTION_DEF(maxpd)
{
	x86_unimplemented(regs, "maxpd");
}

X86_INSTRUCTION_DEF(maxps)
{
	x86_unimplemented(regs, "maxps");
}

X86_INSTRUCTION_DEF(maxsd)
{
	x86_unimplemented(regs, "maxsd");
}

X86_INSTRUCTION_DEF(maxss)
{
	x86_unimplemented(regs, "maxss");
}

X86_INSTRUCTION_DEF(mfence)
{
	x86_unimplemented(regs, "mfence");
}

X86_INSTRUCTION_DEF(minpd)
{
	x86_unimplemented(regs, "minpd");
}

X86_INSTRUCTION_DEF(minps)
{
	x86_unimplemented(regs, "minps");
}

X86_INSTRUCTION_DEF(minsd)
{
	x86_unimplemented(regs, "minsd");
}

X86_INSTRUCTION_DEF(minss)
{
	x86_unimplemented(regs, "minss");
}

X86_INSTRUCTION_DEF(monitor)
{
	x86_unimplemented(regs, "monitor");
}

X86_INSTRUCTION_DEF(montmul)
{
	x86_unimplemented(regs, "montmul");
}

X86_INSTRUCTION_DEF(mov)
{
	x86_move_zero_extend(regs, inst);
}

X86_INSTRUCTION_DEF(movabs)
{
	x86_unimplemented(regs, "movabs");
}

X86_INSTRUCTION_DEF(movapd)
{
	x86_unimplemented(regs, "movapd");
}

X86_INSTRUCTION_DEF(movaps)
{
	x86_unimplemented(regs, "movaps");
}

X86_INSTRUCTION_DEF(movbe)
{
	x86_unimplemented(regs, "movbe");
}

X86_INSTRUCTION_DEF(movd)
{
	x86_unimplemented(regs, "movd");
}

X86_INSTRUCTION_DEF(movddup)
{
	x86_unimplemented(regs, "movddup");
}

X86_INSTRUCTION_DEF(movdq2q)
{
	x86_unimplemented(regs, "movdq2q");
}

X86_INSTRUCTION_DEF(movdqa)
{
	x86_unimplemented(regs, "movdqa");
}

X86_INSTRUCTION_DEF(movdqu)
{
	x86_unimplemented(regs, "movdqu");
}

X86_INSTRUCTION_DEF(movhlps)
{
	x86_unimplemented(regs, "movhlps");
}

X86_INSTRUCTION_DEF(movhpd)
{
	x86_unimplemented(regs, "movhpd");
}

X86_INSTRUCTION_DEF(movhps)
{
	x86_unimplemented(regs, "movhps");
}

X86_INSTRUCTION_DEF(movlhps)
{
	x86_unimplemented(regs, "movlhps");
}

X86_INSTRUCTION_DEF(movlpd)
{
	x86_unimplemented(regs, "movlpd");
}

X86_INSTRUCTION_DEF(movlps)
{
	x86_unimplemented(regs, "movlps");
}

X86_INSTRUCTION_DEF(movmskpd)
{
	x86_unimplemented(regs, "movmskpd");
}

X86_INSTRUCTION_DEF(movmskps)
{
	x86_unimplemented(regs, "movmskps");
}

X86_INSTRUCTION_DEF(movntdq)
{
	x86_unimplemented(regs, "movntdq");
}

X86_INSTRUCTION_DEF(movntdqa)
{
	x86_unimplemented(regs, "movntdqa");
}

X86_INSTRUCTION_DEF(movnti)
{
	x86_unimplemented(regs, "movnti");
}

X86_INSTRUCTION_DEF(movntpd)
{
	x86_unimplemented(regs, "movntpd");
}

X86_INSTRUCTION_DEF(movntps)
{
	x86_unimplemented(regs, "movntps");
}

X86_INSTRUCTION_DEF(movntq)
{
	x86_unimplemented(regs, "movntq");
}

X86_INSTRUCTION_DEF(movntsd)
{
	x86_unimplemented(regs, "movntsd");
}

X86_INSTRUCTION_DEF(movntss)
{
	x86_unimplemented(regs, "movntss");
}

X86_INSTRUCTION_DEF(movq)
{
	x86_unimplemented(regs, "movq");
}

X86_INSTRUCTION_DEF(movq2dq)
{
	x86_unimplemented(regs, "movq2dq");
}

X86_INSTRUCTION_DEF(movsb)
{
	x86_unimplemented(regs, "movsb");
}

X86_INSTRUCTION_DEF(movsd)
{
	x86_unimplemented(regs, "movsd");
}

X86_INSTRUCTION_DEF(movshdup)
{
	x86_unimplemented(regs, "movshdup");
}

X86_INSTRUCTION_DEF(movsldup)
{
	x86_unimplemented(regs, "movsldup");
}

X86_INSTRUCTION_DEF(movsq)
{
	x86_unimplemented(regs, "movsq");
}

X86_INSTRUCTION_DEF(movss)
{
	x86_unimplemented(regs, "movss");
}

X86_INSTRUCTION_DEF(movsw)
{
	x86_unimplemented(regs, "movsw");
}

X86_INSTRUCTION_DEF(movsx)
{
	x86_unimplemented(regs, "movsx");
}

X86_INSTRUCTION_DEF(movsxd)
{
	x86_unimplemented(regs, "movsxd");
}

X86_INSTRUCTION_DEF(movupd)
{
	x86_unimplemented(regs, "movupd");
}

X86_INSTRUCTION_DEF(movups)
{
	x86_unimplemented(regs, "movups");
}

X86_INSTRUCTION_DEF(movzx)
{
	x86_move_zero_extend(regs, inst);
}

X86_INSTRUCTION_DEF(mpsadbw)
{
	x86_unimplemented(regs, "mpsadbw");
}

X86_INSTRUCTION_DEF(mul)
{
	x86_unimplemented(regs, "mul");
}

X86_INSTRUCTION_DEF(mulpd)
{
	x86_unimplemented(regs, "mulpd");
}

X86_INSTRUCTION_DEF(mulps)
{
	x86_unimplemented(regs, "mulps");
}

X86_INSTRUCTION_DEF(mulsd)
{
	x86_unimplemented(regs, "mulsd");
}

X86_INSTRUCTION_DEF(mulss)
{
	x86_unimplemented(regs, "mulss");
}

X86_INSTRUCTION_DEF(mulx)
{
	x86_unimplemented(regs, "mulx");
}

X86_INSTRUCTION_DEF(mwait)
{
	x86_unimplemented(regs, "mwait");
}

X86_INSTRUCTION_DEF(neg)
{
	x86_unimplemented(regs, "neg");
}

X86_INSTRUCTION_DEF(nop)
{
	// do nothing
}

X86_INSTRUCTION_DEF(not)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t writeValue = ~x86_read_destination_operand(destination, regs);
	x86_write_destination_operand(destination, regs, writeValue);
}

X86_INSTRUCTION_DEF(or)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t result = x86_logical_operator(regs, rflags, inst, [](uint64_t left, uint64_t right) { return left | right; });
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(orpd)
{
	x86_unimplemented(regs, "orpd");
}

X86_INSTRUCTION_DEF(orps)
{
	x86_unimplemented(regs, "orps");
}

X86_INSTRUCTION_DEF(out)
{
	x86_unimplemented(regs, "out");
}

X86_INSTRUCTION_DEF(outsb)
{
	x86_unimplemented(regs, "outsb");
}

X86_INSTRUCTION_DEF(outsd)
{
	x86_unimplemented(regs, "outsd");
}

X86_INSTRUCTION_DEF(outsw)
{
	x86_unimplemented(regs, "outsw");
}

X86_INSTRUCTION_DEF(pabsb)
{
	x86_unimplemented(regs, "pabsb");
}

X86_INSTRUCTION_DEF(pabsd)
{
	x86_unimplemented(regs, "pabsd");
}

X86_INSTRUCTION_DEF(pabsw)
{
	x86_unimplemented(regs, "pabsw");
}

X86_INSTRUCTION_DEF(packssdw)
{
	x86_unimplemented(regs, "packssdw");
}

X86_INSTRUCTION_DEF(packsswb)
{
	x86_unimplemented(regs, "packsswb");
}

X86_INSTRUCTION_DEF(packusdw)
{
	x86_unimplemented(regs, "packusdw");
}

X86_INSTRUCTION_DEF(packuswb)
{
	x86_unimplemented(regs, "packuswb");
}

X86_INSTRUCTION_DEF(paddb)
{
	x86_unimplemented(regs, "paddb");
}

X86_INSTRUCTION_DEF(paddd)
{
	x86_unimplemented(regs, "paddd");
}

X86_INSTRUCTION_DEF(paddq)
{
	x86_unimplemented(regs, "paddq");
}

X86_INSTRUCTION_DEF(paddsb)
{
	x86_unimplemented(regs, "paddsb");
}

X86_INSTRUCTION_DEF(paddsw)
{
	x86_unimplemented(regs, "paddsw");
}

X86_INSTRUCTION_DEF(paddusb)
{
	x86_unimplemented(regs, "paddusb");
}

X86_INSTRUCTION_DEF(paddusw)
{
	x86_unimplemented(regs, "paddusw");
}

X86_INSTRUCTION_DEF(paddw)
{
	x86_unimplemented(regs, "paddw");
}

X86_INSTRUCTION_DEF(palignr)
{
	x86_unimplemented(regs, "palignr");
}

X86_INSTRUCTION_DEF(pand)
{
	x86_unimplemented(regs, "pand");
}

X86_INSTRUCTION_DEF(pandn)
{
	x86_unimplemented(regs, "pandn");
}

X86_INSTRUCTION_DEF(pause)
{
	x86_unimplemented(regs, "pause");
}

X86_INSTRUCTION_DEF(pavgb)
{
	x86_unimplemented(regs, "pavgb");
}

X86_INSTRUCTION_DEF(pavgusb)
{
	x86_unimplemented(regs, "pavgusb");
}

X86_INSTRUCTION_DEF(pavgw)
{
	x86_unimplemented(regs, "pavgw");
}

X86_INSTRUCTION_DEF(pblendvb)
{
	x86_unimplemented(regs, "pblendvb");
}

X86_INSTRUCTION_DEF(pblendw)
{
	x86_unimplemented(regs, "pblendw");
}

X86_INSTRUCTION_DEF(pclmulqdq)
{
	x86_unimplemented(regs, "pclmulqdq");
}

X86_INSTRUCTION_DEF(pcmpeqb)
{
	x86_unimplemented(regs, "pcmpeqb");
}

X86_INSTRUCTION_DEF(pcmpeqd)
{
	x86_unimplemented(regs, "pcmpeqd");
}

X86_INSTRUCTION_DEF(pcmpeqq)
{
	x86_unimplemented(regs, "pcmpeqq");
}

X86_INSTRUCTION_DEF(pcmpeqw)
{
	x86_unimplemented(regs, "pcmpeqw");
}

X86_INSTRUCTION_DEF(pcmpestri)
{
	x86_unimplemented(regs, "pcmpestri");
}

X86_INSTRUCTION_DEF(pcmpestrm)
{
	x86_unimplemented(regs, "pcmpestrm");
}

X86_INSTRUCTION_DEF(pcmpgtb)
{
	x86_unimplemented(regs, "pcmpgtb");
}

X86_INSTRUCTION_DEF(pcmpgtd)
{
	x86_unimplemented(regs, "pcmpgtd");
}

X86_INSTRUCTION_DEF(pcmpgtq)
{
	x86_unimplemented(regs, "pcmpgtq");
}

X86_INSTRUCTION_DEF(pcmpgtw)
{
	x86_unimplemented(regs, "pcmpgtw");
}

X86_INSTRUCTION_DEF(pcmpistri)
{
	x86_unimplemented(regs, "pcmpistri");
}

X86_INSTRUCTION_DEF(pcmpistrm)
{
	x86_unimplemented(regs, "pcmpistrm");
}

X86_INSTRUCTION_DEF(pdep)
{
	x86_unimplemented(regs, "pdep");
}

X86_INSTRUCTION_DEF(pext)
{
	x86_unimplemented(regs, "pext");
}

X86_INSTRUCTION_DEF(pextrb)
{
	x86_unimplemented(regs, "pextrb");
}

X86_INSTRUCTION_DEF(pextrd)
{
	x86_unimplemented(regs, "pextrd");
}

X86_INSTRUCTION_DEF(pextrq)
{
	x86_unimplemented(regs, "pextrq");
}

X86_INSTRUCTION_DEF(pextrw)
{
	x86_unimplemented(regs, "pextrw");
}

X86_INSTRUCTION_DEF(pf2id)
{
	x86_unimplemented(regs, "pf2id");
}

X86_INSTRUCTION_DEF(pf2iw)
{
	x86_unimplemented(regs, "pf2iw");
}

X86_INSTRUCTION_DEF(pfacc)
{
	x86_unimplemented(regs, "pfacc");
}

X86_INSTRUCTION_DEF(pfadd)
{
	x86_unimplemented(regs, "pfadd");
}

X86_INSTRUCTION_DEF(pfcmpeq)
{
	x86_unimplemented(regs, "pfcmpeq");
}

X86_INSTRUCTION_DEF(pfcmpge)
{
	x86_unimplemented(regs, "pfcmpge");
}

X86_INSTRUCTION_DEF(pfcmpgt)
{
	x86_unimplemented(regs, "pfcmpgt");
}

X86_INSTRUCTION_DEF(pfmax)
{
	x86_unimplemented(regs, "pfmax");
}

X86_INSTRUCTION_DEF(pfmin)
{
	x86_unimplemented(regs, "pfmin");
}

X86_INSTRUCTION_DEF(pfmul)
{
	x86_unimplemented(regs, "pfmul");
}

X86_INSTRUCTION_DEF(pfnacc)
{
	x86_unimplemented(regs, "pfnacc");
}

X86_INSTRUCTION_DEF(pfpnacc)
{
	x86_unimplemented(regs, "pfpnacc");
}

X86_INSTRUCTION_DEF(pfrcp)
{
	x86_unimplemented(regs, "pfrcp");
}

X86_INSTRUCTION_DEF(pfrcpit1)
{
	x86_unimplemented(regs, "pfrcpit1");
}

X86_INSTRUCTION_DEF(pfrcpit2)
{
	x86_unimplemented(regs, "pfrcpit2");
}

X86_INSTRUCTION_DEF(pfrsqit1)
{
	x86_unimplemented(regs, "pfrsqit1");
}

X86_INSTRUCTION_DEF(pfrsqrt)
{
	x86_unimplemented(regs, "pfrsqrt");
}

X86_INSTRUCTION_DEF(pfsub)
{
	x86_unimplemented(regs, "pfsub");
}

X86_INSTRUCTION_DEF(pfsubr)
{
	x86_unimplemented(regs, "pfsubr");
}

X86_INSTRUCTION_DEF(phaddd)
{
	x86_unimplemented(regs, "phaddd");
}

X86_INSTRUCTION_DEF(phaddsw)
{
	x86_unimplemented(regs, "phaddsw");
}

X86_INSTRUCTION_DEF(phaddw)
{
	x86_unimplemented(regs, "phaddw");
}

X86_INSTRUCTION_DEF(phminposuw)
{
	x86_unimplemented(regs, "phminposuw");
}

X86_INSTRUCTION_DEF(phsubd)
{
	x86_unimplemented(regs, "phsubd");
}

X86_INSTRUCTION_DEF(phsubsw)
{
	x86_unimplemented(regs, "phsubsw");
}

X86_INSTRUCTION_DEF(phsubw)
{
	x86_unimplemented(regs, "phsubw");
}

X86_INSTRUCTION_DEF(pi2fd)
{
	x86_unimplemented(regs, "pi2fd");
}

X86_INSTRUCTION_DEF(pi2fw)
{
	x86_unimplemented(regs, "pi2fw");
}

X86_INSTRUCTION_DEF(pinsrb)
{
	x86_unimplemented(regs, "pinsrb");
}

X86_INSTRUCTION_DEF(pinsrd)
{
	x86_unimplemented(regs, "pinsrd");
}

X86_INSTRUCTION_DEF(pinsrq)
{
	x86_unimplemented(regs, "pinsrq");
}

X86_INSTRUCTION_DEF(pinsrw)
{
	x86_unimplemented(regs, "pinsrw");
}

X86_INSTRUCTION_DEF(pmaddubsw)
{
	x86_unimplemented(regs, "pmaddubsw");
}

X86_INSTRUCTION_DEF(pmaddwd)
{
	x86_unimplemented(regs, "pmaddwd");
}

X86_INSTRUCTION_DEF(pmaxsb)
{
	x86_unimplemented(regs, "pmaxsb");
}

X86_INSTRUCTION_DEF(pmaxsd)
{
	x86_unimplemented(regs, "pmaxsd");
}

X86_INSTRUCTION_DEF(pmaxsw)
{
	x86_unimplemented(regs, "pmaxsw");
}

X86_INSTRUCTION_DEF(pmaxub)
{
	x86_unimplemented(regs, "pmaxub");
}

X86_INSTRUCTION_DEF(pmaxud)
{
	x86_unimplemented(regs, "pmaxud");
}

X86_INSTRUCTION_DEF(pmaxuw)
{
	x86_unimplemented(regs, "pmaxuw");
}

X86_INSTRUCTION_DEF(pminsb)
{
	x86_unimplemented(regs, "pminsb");
}

X86_INSTRUCTION_DEF(pminsd)
{
	x86_unimplemented(regs, "pminsd");
}

X86_INSTRUCTION_DEF(pminsw)
{
	x86_unimplemented(regs, "pminsw");
}

X86_INSTRUCTION_DEF(pminub)
{
	x86_unimplemented(regs, "pminub");
}

X86_INSTRUCTION_DEF(pminud)
{
	x86_unimplemented(regs, "pminud");
}

X86_INSTRUCTION_DEF(pminuw)
{
	x86_unimplemented(regs, "pminuw");
}

X86_INSTRUCTION_DEF(pmovmskb)
{
	x86_unimplemented(regs, "pmovmskb");
}

X86_INSTRUCTION_DEF(pmovsxbd)
{
	x86_unimplemented(regs, "pmovsxbd");
}

X86_INSTRUCTION_DEF(pmovsxbq)
{
	x86_unimplemented(regs, "pmovsxbq");
}

X86_INSTRUCTION_DEF(pmovsxbw)
{
	x86_unimplemented(regs, "pmovsxbw");
}

X86_INSTRUCTION_DEF(pmovsxdq)
{
	x86_unimplemented(regs, "pmovsxdq");
}

X86_INSTRUCTION_DEF(pmovsxwd)
{
	x86_unimplemented(regs, "pmovsxwd");
}

X86_INSTRUCTION_DEF(pmovsxwq)
{
	x86_unimplemented(regs, "pmovsxwq");
}

X86_INSTRUCTION_DEF(pmovzxbd)
{
	x86_unimplemented(regs, "pmovzxbd");
}

X86_INSTRUCTION_DEF(pmovzxbq)
{
	x86_unimplemented(regs, "pmovzxbq");
}

X86_INSTRUCTION_DEF(pmovzxbw)
{
	x86_unimplemented(regs, "pmovzxbw");
}

X86_INSTRUCTION_DEF(pmovzxdq)
{
	x86_unimplemented(regs, "pmovzxdq");
}

X86_INSTRUCTION_DEF(pmovzxwd)
{
	x86_unimplemented(regs, "pmovzxwd");
}

X86_INSTRUCTION_DEF(pmovzxwq)
{
	x86_unimplemented(regs, "pmovzxwq");
}

X86_INSTRUCTION_DEF(pmuldq)
{
	x86_unimplemented(regs, "pmuldq");
}

X86_INSTRUCTION_DEF(pmulhrsw)
{
	x86_unimplemented(regs, "pmulhrsw");
}

X86_INSTRUCTION_DEF(pmulhrw)
{
	x86_unimplemented(regs, "pmulhrw");
}

X86_INSTRUCTION_DEF(pmulhuw)
{
	x86_unimplemented(regs, "pmulhuw");
}

X86_INSTRUCTION_DEF(pmulhw)
{
	x86_unimplemented(regs, "pmulhw");
}

X86_INSTRUCTION_DEF(pmulld)
{
	x86_unimplemented(regs, "pmulld");
}

X86_INSTRUCTION_DEF(pmullw)
{
	x86_unimplemented(regs, "pmullw");
}

X86_INSTRUCTION_DEF(pmuludq)
{
	x86_unimplemented(regs, "pmuludq");
}

X86_INSTRUCTION_DEF(pop)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t popped = x86_pop_value(config, regs, destination->size);
	x86_write_destination_operand(destination, regs, popped);
}

X86_INSTRUCTION_DEF(popal)
{
	x86_unimplemented(regs, "popal");
}

X86_INSTRUCTION_DEF(popaw)
{
	x86_unimplemented(regs, "popaw");
}

X86_INSTRUCTION_DEF(popcnt)
{
	x86_unimplemented(regs, "popcnt");
}

X86_INSTRUCTION_DEF(popf)
{
	x86_unimplemented(regs, "popf");
}

X86_INSTRUCTION_DEF(popfd)
{
	x86_unimplemented(regs, "popfd");
}

X86_INSTRUCTION_DEF(popfq)
{
	x86_unimplemented(regs, "popfq");
}

X86_INSTRUCTION_DEF(por)
{
	x86_unimplemented(regs, "por");
}

X86_INSTRUCTION_DEF(prefetch)
{
	x86_unimplemented(regs, "prefetch");
}

X86_INSTRUCTION_DEF(prefetchnta)
{
	x86_unimplemented(regs, "prefetchnta");
}

X86_INSTRUCTION_DEF(prefetcht0)
{
	x86_unimplemented(regs, "prefetcht0");
}

X86_INSTRUCTION_DEF(prefetcht1)
{
	x86_unimplemented(regs, "prefetcht1");
}

X86_INSTRUCTION_DEF(prefetcht2)
{
	x86_unimplemented(regs, "prefetcht2");
}

X86_INSTRUCTION_DEF(prefetchw)
{
	x86_unimplemented(regs, "prefetchw");
}

X86_INSTRUCTION_DEF(psadbw)
{
	x86_unimplemented(regs, "psadbw");
}

X86_INSTRUCTION_DEF(pshufb)
{
	x86_unimplemented(regs, "pshufb");
}

X86_INSTRUCTION_DEF(pshufd)
{
	x86_unimplemented(regs, "pshufd");
}

X86_INSTRUCTION_DEF(pshufhw)
{
	x86_unimplemented(regs, "pshufhw");
}

X86_INSTRUCTION_DEF(pshuflw)
{
	x86_unimplemented(regs, "pshuflw");
}

X86_INSTRUCTION_DEF(pshufw)
{
	x86_unimplemented(regs, "pshufw");
}

X86_INSTRUCTION_DEF(psignb)
{
	x86_unimplemented(regs, "psignb");
}

X86_INSTRUCTION_DEF(psignd)
{
	x86_unimplemented(regs, "psignd");
}

X86_INSTRUCTION_DEF(psignw)
{
	x86_unimplemented(regs, "psignw");
}

X86_INSTRUCTION_DEF(pslld)
{
	x86_unimplemented(regs, "pslld");
}

X86_INSTRUCTION_DEF(pslldq)
{
	x86_unimplemented(regs, "pslldq");
}

X86_INSTRUCTION_DEF(psllq)
{
	x86_unimplemented(regs, "psllq");
}

X86_INSTRUCTION_DEF(psllw)
{
	x86_unimplemented(regs, "psllw");
}

X86_INSTRUCTION_DEF(psrad)
{
	x86_unimplemented(regs, "psrad");
}

X86_INSTRUCTION_DEF(psraw)
{
	x86_unimplemented(regs, "psraw");
}

X86_INSTRUCTION_DEF(psrld)
{
	x86_unimplemented(regs, "psrld");
}

X86_INSTRUCTION_DEF(psrldq)
{
	x86_unimplemented(regs, "psrldq");
}

X86_INSTRUCTION_DEF(psrlq)
{
	x86_unimplemented(regs, "psrlq");
}

X86_INSTRUCTION_DEF(psrlw)
{
	x86_unimplemented(regs, "psrlw");
}

X86_INSTRUCTION_DEF(psubb)
{
	x86_unimplemented(regs, "psubb");
}

X86_INSTRUCTION_DEF(psubd)
{
	x86_unimplemented(regs, "psubd");
}

X86_INSTRUCTION_DEF(psubq)
{
	x86_unimplemented(regs, "psubq");
}

X86_INSTRUCTION_DEF(psubsb)
{
	x86_unimplemented(regs, "psubsb");
}

X86_INSTRUCTION_DEF(psubsw)
{
	x86_unimplemented(regs, "psubsw");
}

X86_INSTRUCTION_DEF(psubusb)
{
	x86_unimplemented(regs, "psubusb");
}

X86_INSTRUCTION_DEF(psubusw)
{
	x86_unimplemented(regs, "psubusw");
}

X86_INSTRUCTION_DEF(psubw)
{
	x86_unimplemented(regs, "psubw");
}

X86_INSTRUCTION_DEF(pswapd)
{
	x86_unimplemented(regs, "pswapd");
}

X86_INSTRUCTION_DEF(ptest)
{
	x86_unimplemented(regs, "ptest");
}

X86_INSTRUCTION_DEF(punpckhbw)
{
	x86_unimplemented(regs, "punpckhbw");
}

X86_INSTRUCTION_DEF(punpckhdq)
{
	x86_unimplemented(regs, "punpckhdq");
}

X86_INSTRUCTION_DEF(punpckhqdq)
{
	x86_unimplemented(regs, "punpckhqdq");
}

X86_INSTRUCTION_DEF(punpckhwd)
{
	x86_unimplemented(regs, "punpckhwd");
}

X86_INSTRUCTION_DEF(punpcklbw)
{
	x86_unimplemented(regs, "punpcklbw");
}

X86_INSTRUCTION_DEF(punpckldq)
{
	x86_unimplemented(regs, "punpckldq");
}

X86_INSTRUCTION_DEF(punpcklqdq)
{
	x86_unimplemented(regs, "punpcklqdq");
}

X86_INSTRUCTION_DEF(punpcklwd)
{
	x86_unimplemented(regs, "punpcklwd");
}

X86_INSTRUCTION_DEF(push)
{
	const cs_x86_op* source = &inst->operands[0];
	uint64_t pushed = x86_read_source_operand(source, regs);
	x86_push_value(config, regs, source->size, pushed);
}

X86_INSTRUCTION_DEF(pushal)
{
	x86_unimplemented(regs, "pushal");
}

X86_INSTRUCTION_DEF(pushaw)
{
	x86_unimplemented(regs, "pushaw");
}

X86_INSTRUCTION_DEF(pushf)
{
	uint64_t flags = 0;
	flags |= rflags->of;
	flags <<= 2;
	flags |= 1;
	flags <<= 2;
	flags |= rflags->sf;
	flags <<= 1;
	flags |= rflags->zf;
	flags <<= 2;
	flags |= rflags->af;
	flags <<= 2;
	flags |= rflags->pf;
	flags <<= 1;
	flags |= 1;
	flags <<= 1;
	flags |= rflags->cf;
	
	size_t size = inst->prefix[2] == 0x66
		? 2 // override 16 bits
		: config->address_size / 8;
	x86_push_value(config, regs, size, flags);
}

X86_INSTRUCTION_DEF(pushfd)
{
	x86_unimplemented(regs, "pushfd");
}

X86_INSTRUCTION_DEF(pushfq)
{
	x86_unimplemented(regs, "pushfq");
}

X86_INSTRUCTION_DEF(pxor)
{
	x86_unimplemented(regs, "pxor");
}

X86_INSTRUCTION_DEF(rcl)
{
	x86_unimplemented(regs, "rcl");
}

X86_INSTRUCTION_DEF(rcpps)
{
	x86_unimplemented(regs, "rcpps");
}

X86_INSTRUCTION_DEF(rcpss)
{
	x86_unimplemented(regs, "rcpss");
}

X86_INSTRUCTION_DEF(rcr)
{
	x86_unimplemented(regs, "rcr");
}

X86_INSTRUCTION_DEF(rdfsbase)
{
	x86_unimplemented(regs, "rdfsbase");
}

X86_INSTRUCTION_DEF(rdgsbase)
{
	x86_unimplemented(regs, "rdgsbase");
}

X86_INSTRUCTION_DEF(rdmsr)
{
	x86_unimplemented(regs, "rdmsr");
}

X86_INSTRUCTION_DEF(rdpmc)
{
	x86_unimplemented(regs, "rdpmc");
}

X86_INSTRUCTION_DEF(rdrand)
{
	x86_unimplemented(regs, "rdrand");
}

X86_INSTRUCTION_DEF(rdseed)
{
	x86_unimplemented(regs, "rdseed");
}

X86_INSTRUCTION_DEF(rdtsc)
{
	x86_unimplemented(regs, "rdtsc");
}

X86_INSTRUCTION_DEF(rdtscp)
{
	x86_unimplemented(regs, "rdtscp");
}

X86_INSTRUCTION_DEF(ret)
{
	x86_ret_intrin(config, regs);
}

X86_INSTRUCTION_DEF(retf)
{
	x86_unimplemented(regs, "retf");
}

X86_INSTRUCTION_DEF(retfq)
{
	x86_unimplemented(regs, "retfq");
}

X86_INSTRUCTION_DEF(rol)
{
	x86_unimplemented(regs, "rol");
}

X86_INSTRUCTION_DEF(ror)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t shiftAmount = x86_read_source_operand(&inst->operands[1], regs);
	shiftAmount &= make_mask(destination->size == 8 ? 6 : 5);
	
	uint64_t leftPart = left >> shiftAmount;
	uint64_t rightPart = (left & make_mask(shiftAmount)) << (destination->size * CHAR_BIT - shiftAmount);
	uint64_t result = leftPart | rightPart;
	
	x86_write_destination_operand(destination, regs, result);
	rflags->cf = result >> (destination->size * CHAR_BIT - 1);
	if (shiftAmount == 1)
	{
		uint8_t topmostBits = result >> (destination->size * CHAR_BIT - 2);
		rflags->of = topmostBits == 1 || topmostBits == 2;
	}
	else
	{
		rflags->of = x86_clobber_bit();
	}
}

X86_INSTRUCTION_DEF(rorx)
{
	x86_unimplemented(regs, "rorx");
}

X86_INSTRUCTION_DEF(roundpd)
{
	x86_unimplemented(regs, "roundpd");
}

X86_INSTRUCTION_DEF(roundps)
{
	x86_unimplemented(regs, "roundps");
}

X86_INSTRUCTION_DEF(roundsd)
{
	x86_unimplemented(regs, "roundsd");
}

X86_INSTRUCTION_DEF(roundss)
{
	x86_unimplemented(regs, "roundss");
}

X86_INSTRUCTION_DEF(rsm)
{
	x86_unimplemented(regs, "rsm");
}

X86_INSTRUCTION_DEF(rsqrtps)
{
	x86_unimplemented(regs, "rsqrtps");
}

X86_INSTRUCTION_DEF(rsqrtss)
{
	x86_unimplemented(regs, "rsqrtss");
}

X86_INSTRUCTION_DEF(sahf)
{
	x86_unimplemented(regs, "sahf");
}

X86_INSTRUCTION_DEF(sal)
{
	x86_unimplemented(regs, "sal");
}

X86_INSTRUCTION_DEF(salc)
{
	x86_unimplemented(regs, "salc");
}

X86_INSTRUCTION_DEF(sar)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	int64_t signedLeft;
	switch (destination->size)
	{
		case 1: signedLeft = make_signed<int8_t>(left); break;
		case 2: signedLeft = make_signed<int16_t>(left); break;
		case 4: signedLeft = make_signed<int32_t>(left); break;
		case 8: signedLeft = make_signed<int64_t>(left); break;
		default: x86_assertion_failure("unknown operand size for shift");
	}
	
	uint64_t shiftAmount = x86_read_source_operand(&inst->operands[1], regs);
	shiftAmount &= make_mask(destination->size == 8 ? 6 : 5);
	int64_t result = signedLeft >> shiftAmount;
	
	x86_write_destination_operand(destination, regs, result);
	rflags->cf = (signedLeft >> (shiftAmount - 1)) & 1;
	rflags->of = shiftAmount == 1 ? 0 : x86_clobber_bit();
	rflags->sf = (result >> (destination->size * CHAR_BIT - 1)) & 1;
	rflags->pf = x86_parity(result);
	rflags->zf = result == 0;
	if (shiftAmount != 0)
	{
		rflags->af = x86_clobber_bit();
	}
}

X86_INSTRUCTION_DEF(sarx)
{
	x86_unimplemented(regs, "sarx");
}

X86_INSTRUCTION_DEF(sbb)
{
	x86_unimplemented(regs, "sbb");
}

X86_INSTRUCTION_DEF(scasb)
{
	x86_unimplemented(regs, "scasb");
}

X86_INSTRUCTION_DEF(scasd)
{
	x86_unimplemented(regs, "scasd");
}

X86_INSTRUCTION_DEF(scasq)
{
	x86_unimplemented(regs, "scasq");
}

X86_INSTRUCTION_DEF(scasw)
{
	x86_unimplemented(regs, "scasw");
}

X86_INSTRUCTION_DEF(seta)
{
	bool cond = x86_cond_above(rflags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setae)
{
	bool cond = x86_cond_above_or_equal(rflags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setb)
{
	bool cond = x86_cond_below(rflags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setbe)
{
	bool cond = x86_cond_below_or_equal(rflags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(sete)
{
	bool cond = x86_cond_equal(rflags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setg)
{
	bool cond = x86_cond_greater(rflags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setge)
{
	bool cond = x86_cond_greater_or_equal(rflags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setl)
{
	bool cond = x86_cond_less(rflags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setle)
{
	bool cond = x86_cond_less_or_equal(rflags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setne)
{
	bool cond = x86_cond_not_equal(rflags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setno)
{
	bool cond = x86_cond_no_overflow(rflags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setnp)
{
	bool cond = x86_cond_no_parity(rflags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setns)
{
	bool cond = x86_cond_no_sign(rflags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(seto)
{
	bool cond = x86_cond_overflow(rflags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setp)
{
	bool cond = x86_cond_parity(rflags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(sets)
{
	bool cond = x86_cond_signed(rflags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(sfence)
{
	x86_unimplemented(regs, "sfence");
}

X86_INSTRUCTION_DEF(sgdt)
{
	x86_unimplemented(regs, "sgdt");
}

X86_INSTRUCTION_DEF(sha1msg1)
{
	x86_unimplemented(regs, "sha1msg1");
}

X86_INSTRUCTION_DEF(sha1msg2)
{
	x86_unimplemented(regs, "sha1msg2");
}

X86_INSTRUCTION_DEF(sha1nexte)
{
	x86_unimplemented(regs, "sha1nexte");
}

X86_INSTRUCTION_DEF(sha1rnds4)
{
	x86_unimplemented(regs, "sha1rnds4");
}

X86_INSTRUCTION_DEF(sha256msg1)
{
	x86_unimplemented(regs, "sha256msg1");
}

X86_INSTRUCTION_DEF(sha256msg2)
{
	x86_unimplemented(regs, "sha256msg2");
}

X86_INSTRUCTION_DEF(sha256rnds2)
{
	x86_unimplemented(regs, "sha256rnds2");
}

X86_INSTRUCTION_DEF(shl)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t shiftAmount = x86_read_source_operand(&inst->operands[1], regs);
	shiftAmount &= make_mask(destination->size == 8 ? 6 : 5);
	uint64_t result = left << shiftAmount;
	
	x86_write_destination_operand(destination, regs, result);
	rflags->cf = (left >> (CHAR_BIT * destination->size - shiftAmount)) & 1;
	if (shiftAmount == 1)
	{
		uint8_t topmostBits = left >> (CHAR_BIT * destination->size - 2) & 3;
		rflags->of = topmostBits == 1 || topmostBits == 2;
	}
	else
	{
		rflags->of = x86_clobber_bit();
	}
	rflags->sf = (result >> (destination->size * CHAR_BIT - 1)) & 1;
	rflags->pf = x86_parity(result);
	rflags->zf = result == 0;
	if (shiftAmount != 0)
	{
		rflags->af = x86_clobber_bit();
	}
}

X86_INSTRUCTION_DEF(shld)
{
	x86_unimplemented(regs, "shld");
}

X86_INSTRUCTION_DEF(shlx)
{
	x86_unimplemented(regs, "shlx");
}

X86_INSTRUCTION_DEF(shr)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t shiftAmount = x86_read_source_operand(&inst->operands[1], regs);
	shiftAmount &= make_mask(destination->size == 8 ? 6 : 5);
	uint64_t result = left >> shiftAmount;
	
	x86_write_destination_operand(destination, regs, result);
	rflags->cf = (left >> (shiftAmount - 1)) & 1;
	rflags->of = shiftAmount == 1 ? (left >> (destination->size * CHAR_BIT - 1)) & 1 : x86_clobber_bit();
	rflags->sf = (result >> (destination->size * CHAR_BIT - 1)) & 1;
	rflags->pf = x86_parity(result);
	rflags->zf = result == 0;
	if (shiftAmount != 0)
	{
		rflags->af = x86_clobber_bit();
	}
}

X86_INSTRUCTION_DEF(shrd)
{
	x86_unimplemented(regs, "shrd");
}

X86_INSTRUCTION_DEF(shrx)
{
	x86_unimplemented(regs, "shrx");
}

X86_INSTRUCTION_DEF(shufpd)
{
	x86_unimplemented(regs, "shufpd");
}

X86_INSTRUCTION_DEF(shufps)
{
	x86_unimplemented(regs, "shufps");
}

X86_INSTRUCTION_DEF(sidt)
{
	x86_unimplemented(regs, "sidt");
}

X86_INSTRUCTION_DEF(skinit)
{
	x86_unimplemented(regs, "skinit");
}

X86_INSTRUCTION_DEF(sldt)
{
	x86_unimplemented(regs, "sldt");
}

X86_INSTRUCTION_DEF(smsw)
{
	x86_unimplemented(regs, "smsw");
}

X86_INSTRUCTION_DEF(sqrtpd)
{
	x86_unimplemented(regs, "sqrtpd");
}

X86_INSTRUCTION_DEF(sqrtps)
{
	x86_unimplemented(regs, "sqrtps");
}

X86_INSTRUCTION_DEF(sqrtsd)
{
	x86_unimplemented(regs, "sqrtsd");
}

X86_INSTRUCTION_DEF(sqrtss)
{
	x86_unimplemented(regs, "sqrtss");
}

X86_INSTRUCTION_DEF(stac)
{
	x86_unimplemented(regs, "stac");
}

X86_INSTRUCTION_DEF(stc)
{
	rflags->cf = 1;
}

X86_INSTRUCTION_DEF(std)
{
	x86_unimplemented(regs, "std");
}

X86_INSTRUCTION_DEF(stgi)
{
	x86_unimplemented(regs, "stgi");
}

X86_INSTRUCTION_DEF(sti)
{
	x86_unimplemented(regs, "sti");
}

X86_INSTRUCTION_DEF(stmxcsr)
{
	x86_unimplemented(regs, "stmxcsr");
}

X86_INSTRUCTION_DEF(stosb)
{
	x86_unimplemented(regs, "stosb");
}

X86_INSTRUCTION_DEF(stosd)
{
	x86_unimplemented(regs, "stosd");
}

X86_INSTRUCTION_DEF(stosq)
{
	x86_unimplemented(regs, "stosq");
}

X86_INSTRUCTION_DEF(stosw)
{
	x86_unimplemented(regs, "stosw");
}

X86_INSTRUCTION_DEF(str)
{
	x86_unimplemented(regs, "str");
}

X86_INSTRUCTION_DEF(sub)
{
	const cs_x86_op* source = &inst->operands[1];
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t right = x86_read_source_operand(source, regs);
	
	memset(rflags, 0, sizeof *rflags);
	uint64_t result = x86_subtract(rflags, destination->size, left, right);
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(subpd)
{
	x86_unimplemented(regs, "subpd");
}

X86_INSTRUCTION_DEF(subps)
{
	x86_unimplemented(regs, "subps");
}

X86_INSTRUCTION_DEF(subsd)
{
	x86_unimplemented(regs, "subsd");
}

X86_INSTRUCTION_DEF(subss)
{
	x86_unimplemented(regs, "subss");
}

X86_INSTRUCTION_DEF(swapgs)
{
	x86_unimplemented(regs, "swapgs");
}

X86_INSTRUCTION_DEF(syscall)
{
	x86_unimplemented(regs, "syscall");
}

X86_INSTRUCTION_DEF(sysenter)
{
	x86_unimplemented(regs, "sysenter");
}

X86_INSTRUCTION_DEF(sysexit)
{
	x86_unimplemented(regs, "sysexit");
}

X86_INSTRUCTION_DEF(sysret)
{
	x86_unimplemented(regs, "sysret");
}

X86_INSTRUCTION_DEF(t1mskc)
{
	x86_unimplemented(regs, "t1mskc");
}

X86_INSTRUCTION_DEF(test)
{
	x86_logical_operator(regs, rflags, inst, [](uint64_t left, uint64_t right) { return left & right; });
}

X86_INSTRUCTION_DEF(tzcnt)
{
	x86_unimplemented(regs, "tzcnt");
}

X86_INSTRUCTION_DEF(tzmsk)
{
	x86_unimplemented(regs, "tzmsk");
}

X86_INSTRUCTION_DEF(ucomisd)
{
	x86_unimplemented(regs, "ucomisd");
}

X86_INSTRUCTION_DEF(ucomiss)
{
	x86_unimplemented(regs, "ucomiss");
}

X86_INSTRUCTION_DEF(ud2)
{
	x86_unimplemented(regs, "ud2");
}

X86_INSTRUCTION_DEF(ud2b)
{
	x86_unimplemented(regs, "ud2b");
}

X86_INSTRUCTION_DEF(unpckhpd)
{
	x86_unimplemented(regs, "unpckhpd");
}

X86_INSTRUCTION_DEF(unpckhps)
{
	x86_unimplemented(regs, "unpckhps");
}

X86_INSTRUCTION_DEF(unpcklpd)
{
	x86_unimplemented(regs, "unpcklpd");
}

X86_INSTRUCTION_DEF(unpcklps)
{
	x86_unimplemented(regs, "unpcklps");
}

X86_INSTRUCTION_DEF(vaddpd)
{
	x86_unimplemented(regs, "vaddpd");
}

X86_INSTRUCTION_DEF(vaddps)
{
	x86_unimplemented(regs, "vaddps");
}

X86_INSTRUCTION_DEF(vaddsd)
{
	x86_unimplemented(regs, "vaddsd");
}

X86_INSTRUCTION_DEF(vaddss)
{
	x86_unimplemented(regs, "vaddss");
}

X86_INSTRUCTION_DEF(vaddsubpd)
{
	x86_unimplemented(regs, "vaddsubpd");
}

X86_INSTRUCTION_DEF(vaddsubps)
{
	x86_unimplemented(regs, "vaddsubps");
}

X86_INSTRUCTION_DEF(vaesdec)
{
	x86_unimplemented(regs, "vaesdec");
}

X86_INSTRUCTION_DEF(vaesdeclast)
{
	x86_unimplemented(regs, "vaesdeclast");
}

X86_INSTRUCTION_DEF(vaesenc)
{
	x86_unimplemented(regs, "vaesenc");
}

X86_INSTRUCTION_DEF(vaesenclast)
{
	x86_unimplemented(regs, "vaesenclast");
}

X86_INSTRUCTION_DEF(vaesimc)
{
	x86_unimplemented(regs, "vaesimc");
}

X86_INSTRUCTION_DEF(vaeskeygenassist)
{
	x86_unimplemented(regs, "vaeskeygenassist");
}

X86_INSTRUCTION_DEF(valignd)
{
	x86_unimplemented(regs, "valignd");
}

X86_INSTRUCTION_DEF(valignq)
{
	x86_unimplemented(regs, "valignq");
}

X86_INSTRUCTION_DEF(vandnpd)
{
	x86_unimplemented(regs, "vandnpd");
}

X86_INSTRUCTION_DEF(vandnps)
{
	x86_unimplemented(regs, "vandnps");
}

X86_INSTRUCTION_DEF(vandpd)
{
	x86_unimplemented(regs, "vandpd");
}

X86_INSTRUCTION_DEF(vandps)
{
	x86_unimplemented(regs, "vandps");
}

X86_INSTRUCTION_DEF(vblendmpd)
{
	x86_unimplemented(regs, "vblendmpd");
}

X86_INSTRUCTION_DEF(vblendmps)
{
	x86_unimplemented(regs, "vblendmps");
}

X86_INSTRUCTION_DEF(vblendpd)
{
	x86_unimplemented(regs, "vblendpd");
}

X86_INSTRUCTION_DEF(vblendps)
{
	x86_unimplemented(regs, "vblendps");
}

X86_INSTRUCTION_DEF(vblendvpd)
{
	x86_unimplemented(regs, "vblendvpd");
}

X86_INSTRUCTION_DEF(vblendvps)
{
	x86_unimplemented(regs, "vblendvps");
}

X86_INSTRUCTION_DEF(vbroadcastf128)
{
	x86_unimplemented(regs, "vbroadcastf128");
}

X86_INSTRUCTION_DEF(vbroadcasti128)
{
	x86_unimplemented(regs, "vbroadcasti128");
}

X86_INSTRUCTION_DEF(vbroadcasti32x4)
{
	x86_unimplemented(regs, "vbroadcasti32x4");
}

X86_INSTRUCTION_DEF(vbroadcasti64x4)
{
	x86_unimplemented(regs, "vbroadcasti64x4");
}

X86_INSTRUCTION_DEF(vbroadcastsd)
{
	x86_unimplemented(regs, "vbroadcastsd");
}

X86_INSTRUCTION_DEF(vbroadcastss)
{
	x86_unimplemented(regs, "vbroadcastss");
}

X86_INSTRUCTION_DEF(vcmp)
{
	x86_unimplemented(regs, "vcmp");
}

X86_INSTRUCTION_DEF(vcmppd)
{
	x86_unimplemented(regs, "vcmppd");
}

X86_INSTRUCTION_DEF(vcmpps)
{
	x86_unimplemented(regs, "vcmpps");
}

X86_INSTRUCTION_DEF(vcmpsd)
{
	x86_unimplemented(regs, "vcmpsd");
}

X86_INSTRUCTION_DEF(vcmpss)
{
	x86_unimplemented(regs, "vcmpss");
}

X86_INSTRUCTION_DEF(vcomisd)
{
	x86_unimplemented(regs, "vcomisd");
}

X86_INSTRUCTION_DEF(vcomiss)
{
	x86_unimplemented(regs, "vcomiss");
}

X86_INSTRUCTION_DEF(vcvtdq2pd)
{
	x86_unimplemented(regs, "vcvtdq2pd");
}

X86_INSTRUCTION_DEF(vcvtdq2ps)
{
	x86_unimplemented(regs, "vcvtdq2ps");
}

X86_INSTRUCTION_DEF(vcvtpd2dq)
{
	x86_unimplemented(regs, "vcvtpd2dq");
}

X86_INSTRUCTION_DEF(vcvtpd2dqx)
{
	x86_unimplemented(regs, "vcvtpd2dqx");
}

X86_INSTRUCTION_DEF(vcvtpd2ps)
{
	x86_unimplemented(regs, "vcvtpd2ps");
}

X86_INSTRUCTION_DEF(vcvtpd2psx)
{
	x86_unimplemented(regs, "vcvtpd2psx");
}

X86_INSTRUCTION_DEF(vcvtpd2udq)
{
	x86_unimplemented(regs, "vcvtpd2udq");
}

X86_INSTRUCTION_DEF(vcvtph2ps)
{
	x86_unimplemented(regs, "vcvtph2ps");
}

X86_INSTRUCTION_DEF(vcvtps2dq)
{
	x86_unimplemented(regs, "vcvtps2dq");
}

X86_INSTRUCTION_DEF(vcvtps2pd)
{
	x86_unimplemented(regs, "vcvtps2pd");
}

X86_INSTRUCTION_DEF(vcvtps2ph)
{
	x86_unimplemented(regs, "vcvtps2ph");
}

X86_INSTRUCTION_DEF(vcvtps2udq)
{
	x86_unimplemented(regs, "vcvtps2udq");
}

X86_INSTRUCTION_DEF(vcvtsd2si)
{
	x86_unimplemented(regs, "vcvtsd2si");
}

X86_INSTRUCTION_DEF(vcvtsd2ss)
{
	x86_unimplemented(regs, "vcvtsd2ss");
}

X86_INSTRUCTION_DEF(vcvtsd2usi)
{
	x86_unimplemented(regs, "vcvtsd2usi");
}

X86_INSTRUCTION_DEF(vcvtsi2sd)
{
	x86_unimplemented(regs, "vcvtsi2sd");
}

X86_INSTRUCTION_DEF(vcvtsi2ss)
{
	x86_unimplemented(regs, "vcvtsi2ss");
}

X86_INSTRUCTION_DEF(vcvtss2sd)
{
	x86_unimplemented(regs, "vcvtss2sd");
}

X86_INSTRUCTION_DEF(vcvtss2si)
{
	x86_unimplemented(regs, "vcvtss2si");
}

X86_INSTRUCTION_DEF(vcvtss2usi)
{
	x86_unimplemented(regs, "vcvtss2usi");
}

X86_INSTRUCTION_DEF(vcvttpd2dq)
{
	x86_unimplemented(regs, "vcvttpd2dq");
}

X86_INSTRUCTION_DEF(vcvttpd2dqx)
{
	x86_unimplemented(regs, "vcvttpd2dqx");
}

X86_INSTRUCTION_DEF(vcvttpd2udq)
{
	x86_unimplemented(regs, "vcvttpd2udq");
}

X86_INSTRUCTION_DEF(vcvttps2dq)
{
	x86_unimplemented(regs, "vcvttps2dq");
}

X86_INSTRUCTION_DEF(vcvttps2udq)
{
	x86_unimplemented(regs, "vcvttps2udq");
}

X86_INSTRUCTION_DEF(vcvttsd2si)
{
	x86_unimplemented(regs, "vcvttsd2si");
}

X86_INSTRUCTION_DEF(vcvttsd2usi)
{
	x86_unimplemented(regs, "vcvttsd2usi");
}

X86_INSTRUCTION_DEF(vcvttss2si)
{
	x86_unimplemented(regs, "vcvttss2si");
}

X86_INSTRUCTION_DEF(vcvttss2usi)
{
	x86_unimplemented(regs, "vcvttss2usi");
}

X86_INSTRUCTION_DEF(vcvtudq2pd)
{
	x86_unimplemented(regs, "vcvtudq2pd");
}

X86_INSTRUCTION_DEF(vcvtudq2ps)
{
	x86_unimplemented(regs, "vcvtudq2ps");
}

X86_INSTRUCTION_DEF(vcvtusi2sd)
{
	x86_unimplemented(regs, "vcvtusi2sd");
}

X86_INSTRUCTION_DEF(vcvtusi2ss)
{
	x86_unimplemented(regs, "vcvtusi2ss");
}

X86_INSTRUCTION_DEF(vdivpd)
{
	x86_unimplemented(regs, "vdivpd");
}

X86_INSTRUCTION_DEF(vdivps)
{
	x86_unimplemented(regs, "vdivps");
}

X86_INSTRUCTION_DEF(vdivsd)
{
	x86_unimplemented(regs, "vdivsd");
}

X86_INSTRUCTION_DEF(vdivss)
{
	x86_unimplemented(regs, "vdivss");
}

X86_INSTRUCTION_DEF(vdppd)
{
	x86_unimplemented(regs, "vdppd");
}

X86_INSTRUCTION_DEF(vdpps)
{
	x86_unimplemented(regs, "vdpps");
}

X86_INSTRUCTION_DEF(verr)
{
	x86_unimplemented(regs, "verr");
}

X86_INSTRUCTION_DEF(verw)
{
	x86_unimplemented(regs, "verw");
}

X86_INSTRUCTION_DEF(vextractf128)
{
	x86_unimplemented(regs, "vextractf128");
}

X86_INSTRUCTION_DEF(vextractf32x4)
{
	x86_unimplemented(regs, "vextractf32x4");
}

X86_INSTRUCTION_DEF(vextractf64x4)
{
	x86_unimplemented(regs, "vextractf64x4");
}

X86_INSTRUCTION_DEF(vextracti128)
{
	x86_unimplemented(regs, "vextracti128");
}

X86_INSTRUCTION_DEF(vextracti32x4)
{
	x86_unimplemented(regs, "vextracti32x4");
}

X86_INSTRUCTION_DEF(vextracti64x4)
{
	x86_unimplemented(regs, "vextracti64x4");
}

X86_INSTRUCTION_DEF(vextractps)
{
	x86_unimplemented(regs, "vextractps");
}

X86_INSTRUCTION_DEF(vfmadd132pd)
{
	x86_unimplemented(regs, "vfmadd132pd");
}

X86_INSTRUCTION_DEF(vfmadd132ps)
{
	x86_unimplemented(regs, "vfmadd132ps");
}

X86_INSTRUCTION_DEF(vfmadd132sd)
{
	x86_unimplemented(regs, "vfmadd132sd");
}

X86_INSTRUCTION_DEF(vfmadd132ss)
{
	x86_unimplemented(regs, "vfmadd132ss");
}

X86_INSTRUCTION_DEF(vfmadd213pd)
{
	x86_unimplemented(regs, "vfmadd213pd");
}

X86_INSTRUCTION_DEF(vfmadd213ps)
{
	x86_unimplemented(regs, "vfmadd213ps");
}

X86_INSTRUCTION_DEF(vfmadd213sd)
{
	x86_unimplemented(regs, "vfmadd213sd");
}

X86_INSTRUCTION_DEF(vfmadd213ss)
{
	x86_unimplemented(regs, "vfmadd213ss");
}

X86_INSTRUCTION_DEF(vfmadd231pd)
{
	x86_unimplemented(regs, "vfmadd231pd");
}

X86_INSTRUCTION_DEF(vfmadd231ps)
{
	x86_unimplemented(regs, "vfmadd231ps");
}

X86_INSTRUCTION_DEF(vfmadd231sd)
{
	x86_unimplemented(regs, "vfmadd231sd");
}

X86_INSTRUCTION_DEF(vfmadd231ss)
{
	x86_unimplemented(regs, "vfmadd231ss");
}

X86_INSTRUCTION_DEF(vfmaddpd)
{
	x86_unimplemented(regs, "vfmaddpd");
}

X86_INSTRUCTION_DEF(vfmaddps)
{
	x86_unimplemented(regs, "vfmaddps");
}

X86_INSTRUCTION_DEF(vfmaddsd)
{
	x86_unimplemented(regs, "vfmaddsd");
}

X86_INSTRUCTION_DEF(vfmaddss)
{
	x86_unimplemented(regs, "vfmaddss");
}

X86_INSTRUCTION_DEF(vfmaddsub132pd)
{
	x86_unimplemented(regs, "vfmaddsub132pd");
}

X86_INSTRUCTION_DEF(vfmaddsub132ps)
{
	x86_unimplemented(regs, "vfmaddsub132ps");
}

X86_INSTRUCTION_DEF(vfmaddsub213pd)
{
	x86_unimplemented(regs, "vfmaddsub213pd");
}

X86_INSTRUCTION_DEF(vfmaddsub213ps)
{
	x86_unimplemented(regs, "vfmaddsub213ps");
}

X86_INSTRUCTION_DEF(vfmaddsub231pd)
{
	x86_unimplemented(regs, "vfmaddsub231pd");
}

X86_INSTRUCTION_DEF(vfmaddsub231ps)
{
	x86_unimplemented(regs, "vfmaddsub231ps");
}

X86_INSTRUCTION_DEF(vfmaddsubpd)
{
	x86_unimplemented(regs, "vfmaddsubpd");
}

X86_INSTRUCTION_DEF(vfmaddsubps)
{
	x86_unimplemented(regs, "vfmaddsubps");
}

X86_INSTRUCTION_DEF(vfmsub132pd)
{
	x86_unimplemented(regs, "vfmsub132pd");
}

X86_INSTRUCTION_DEF(vfmsub132ps)
{
	x86_unimplemented(regs, "vfmsub132ps");
}

X86_INSTRUCTION_DEF(vfmsub132sd)
{
	x86_unimplemented(regs, "vfmsub132sd");
}

X86_INSTRUCTION_DEF(vfmsub132ss)
{
	x86_unimplemented(regs, "vfmsub132ss");
}

X86_INSTRUCTION_DEF(vfmsub213pd)
{
	x86_unimplemented(regs, "vfmsub213pd");
}

X86_INSTRUCTION_DEF(vfmsub213ps)
{
	x86_unimplemented(regs, "vfmsub213ps");
}

X86_INSTRUCTION_DEF(vfmsub213sd)
{
	x86_unimplemented(regs, "vfmsub213sd");
}

X86_INSTRUCTION_DEF(vfmsub213ss)
{
	x86_unimplemented(regs, "vfmsub213ss");
}

X86_INSTRUCTION_DEF(vfmsub231pd)
{
	x86_unimplemented(regs, "vfmsub231pd");
}

X86_INSTRUCTION_DEF(vfmsub231ps)
{
	x86_unimplemented(regs, "vfmsub231ps");
}

X86_INSTRUCTION_DEF(vfmsub231sd)
{
	x86_unimplemented(regs, "vfmsub231sd");
}

X86_INSTRUCTION_DEF(vfmsub231ss)
{
	x86_unimplemented(regs, "vfmsub231ss");
}

X86_INSTRUCTION_DEF(vfmsubadd132pd)
{
	x86_unimplemented(regs, "vfmsubadd132pd");
}

X86_INSTRUCTION_DEF(vfmsubadd132ps)
{
	x86_unimplemented(regs, "vfmsubadd132ps");
}

X86_INSTRUCTION_DEF(vfmsubadd213pd)
{
	x86_unimplemented(regs, "vfmsubadd213pd");
}

X86_INSTRUCTION_DEF(vfmsubadd213ps)
{
	x86_unimplemented(regs, "vfmsubadd213ps");
}

X86_INSTRUCTION_DEF(vfmsubadd231pd)
{
	x86_unimplemented(regs, "vfmsubadd231pd");
}

X86_INSTRUCTION_DEF(vfmsubadd231ps)
{
	x86_unimplemented(regs, "vfmsubadd231ps");
}

X86_INSTRUCTION_DEF(vfmsubaddpd)
{
	x86_unimplemented(regs, "vfmsubaddpd");
}

X86_INSTRUCTION_DEF(vfmsubaddps)
{
	x86_unimplemented(regs, "vfmsubaddps");
}

X86_INSTRUCTION_DEF(vfmsubpd)
{
	x86_unimplemented(regs, "vfmsubpd");
}

X86_INSTRUCTION_DEF(vfmsubps)
{
	x86_unimplemented(regs, "vfmsubps");
}

X86_INSTRUCTION_DEF(vfmsubsd)
{
	x86_unimplemented(regs, "vfmsubsd");
}

X86_INSTRUCTION_DEF(vfmsubss)
{
	x86_unimplemented(regs, "vfmsubss");
}

X86_INSTRUCTION_DEF(vfnmadd132pd)
{
	x86_unimplemented(regs, "vfnmadd132pd");
}

X86_INSTRUCTION_DEF(vfnmadd132ps)
{
	x86_unimplemented(regs, "vfnmadd132ps");
}

X86_INSTRUCTION_DEF(vfnmadd132sd)
{
	x86_unimplemented(regs, "vfnmadd132sd");
}

X86_INSTRUCTION_DEF(vfnmadd132ss)
{
	x86_unimplemented(regs, "vfnmadd132ss");
}

X86_INSTRUCTION_DEF(vfnmadd213pd)
{
	x86_unimplemented(regs, "vfnmadd213pd");
}

X86_INSTRUCTION_DEF(vfnmadd213ps)
{
	x86_unimplemented(regs, "vfnmadd213ps");
}

X86_INSTRUCTION_DEF(vfnmadd213sd)
{
	x86_unimplemented(regs, "vfnmadd213sd");
}

X86_INSTRUCTION_DEF(vfnmadd213ss)
{
	x86_unimplemented(regs, "vfnmadd213ss");
}

X86_INSTRUCTION_DEF(vfnmadd231pd)
{
	x86_unimplemented(regs, "vfnmadd231pd");
}

X86_INSTRUCTION_DEF(vfnmadd231ps)
{
	x86_unimplemented(regs, "vfnmadd231ps");
}

X86_INSTRUCTION_DEF(vfnmadd231sd)
{
	x86_unimplemented(regs, "vfnmadd231sd");
}

X86_INSTRUCTION_DEF(vfnmadd231ss)
{
	x86_unimplemented(regs, "vfnmadd231ss");
}

X86_INSTRUCTION_DEF(vfnmaddpd)
{
	x86_unimplemented(regs, "vfnmaddpd");
}

X86_INSTRUCTION_DEF(vfnmaddps)
{
	x86_unimplemented(regs, "vfnmaddps");
}

X86_INSTRUCTION_DEF(vfnmaddsd)
{
	x86_unimplemented(regs, "vfnmaddsd");
}

X86_INSTRUCTION_DEF(vfnmaddss)
{
	x86_unimplemented(regs, "vfnmaddss");
}

X86_INSTRUCTION_DEF(vfnmsub132pd)
{
	x86_unimplemented(regs, "vfnmsub132pd");
}

X86_INSTRUCTION_DEF(vfnmsub132ps)
{
	x86_unimplemented(regs, "vfnmsub132ps");
}

X86_INSTRUCTION_DEF(vfnmsub132sd)
{
	x86_unimplemented(regs, "vfnmsub132sd");
}

X86_INSTRUCTION_DEF(vfnmsub132ss)
{
	x86_unimplemented(regs, "vfnmsub132ss");
}

X86_INSTRUCTION_DEF(vfnmsub213pd)
{
	x86_unimplemented(regs, "vfnmsub213pd");
}

X86_INSTRUCTION_DEF(vfnmsub213ps)
{
	x86_unimplemented(regs, "vfnmsub213ps");
}

X86_INSTRUCTION_DEF(vfnmsub213sd)
{
	x86_unimplemented(regs, "vfnmsub213sd");
}

X86_INSTRUCTION_DEF(vfnmsub213ss)
{
	x86_unimplemented(regs, "vfnmsub213ss");
}

X86_INSTRUCTION_DEF(vfnmsub231pd)
{
	x86_unimplemented(regs, "vfnmsub231pd");
}

X86_INSTRUCTION_DEF(vfnmsub231ps)
{
	x86_unimplemented(regs, "vfnmsub231ps");
}

X86_INSTRUCTION_DEF(vfnmsub231sd)
{
	x86_unimplemented(regs, "vfnmsub231sd");
}

X86_INSTRUCTION_DEF(vfnmsub231ss)
{
	x86_unimplemented(regs, "vfnmsub231ss");
}

X86_INSTRUCTION_DEF(vfnmsubpd)
{
	x86_unimplemented(regs, "vfnmsubpd");
}

X86_INSTRUCTION_DEF(vfnmsubps)
{
	x86_unimplemented(regs, "vfnmsubps");
}

X86_INSTRUCTION_DEF(vfnmsubsd)
{
	x86_unimplemented(regs, "vfnmsubsd");
}

X86_INSTRUCTION_DEF(vfnmsubss)
{
	x86_unimplemented(regs, "vfnmsubss");
}

X86_INSTRUCTION_DEF(vfrczpd)
{
	x86_unimplemented(regs, "vfrczpd");
}

X86_INSTRUCTION_DEF(vfrczps)
{
	x86_unimplemented(regs, "vfrczps");
}

X86_INSTRUCTION_DEF(vfrczsd)
{
	x86_unimplemented(regs, "vfrczsd");
}

X86_INSTRUCTION_DEF(vfrczss)
{
	x86_unimplemented(regs, "vfrczss");
}

X86_INSTRUCTION_DEF(vgatherdpd)
{
	x86_unimplemented(regs, "vgatherdpd");
}

X86_INSTRUCTION_DEF(vgatherdps)
{
	x86_unimplemented(regs, "vgatherdps");
}

X86_INSTRUCTION_DEF(vgatherpf0dpd)
{
	x86_unimplemented(regs, "vgatherpf0dpd");
}

X86_INSTRUCTION_DEF(vgatherpf0dps)
{
	x86_unimplemented(regs, "vgatherpf0dps");
}

X86_INSTRUCTION_DEF(vgatherpf0qpd)
{
	x86_unimplemented(regs, "vgatherpf0qpd");
}

X86_INSTRUCTION_DEF(vgatherpf0qps)
{
	x86_unimplemented(regs, "vgatherpf0qps");
}

X86_INSTRUCTION_DEF(vgatherpf1dpd)
{
	x86_unimplemented(regs, "vgatherpf1dpd");
}

X86_INSTRUCTION_DEF(vgatherpf1dps)
{
	x86_unimplemented(regs, "vgatherpf1dps");
}

X86_INSTRUCTION_DEF(vgatherpf1qpd)
{
	x86_unimplemented(regs, "vgatherpf1qpd");
}

X86_INSTRUCTION_DEF(vgatherpf1qps)
{
	x86_unimplemented(regs, "vgatherpf1qps");
}

X86_INSTRUCTION_DEF(vgatherqpd)
{
	x86_unimplemented(regs, "vgatherqpd");
}

X86_INSTRUCTION_DEF(vgatherqps)
{
	x86_unimplemented(regs, "vgatherqps");
}

X86_INSTRUCTION_DEF(vhaddpd)
{
	x86_unimplemented(regs, "vhaddpd");
}

X86_INSTRUCTION_DEF(vhaddps)
{
	x86_unimplemented(regs, "vhaddps");
}

X86_INSTRUCTION_DEF(vhsubpd)
{
	x86_unimplemented(regs, "vhsubpd");
}

X86_INSTRUCTION_DEF(vhsubps)
{
	x86_unimplemented(regs, "vhsubps");
}

X86_INSTRUCTION_DEF(vinsertf128)
{
	x86_unimplemented(regs, "vinsertf128");
}

X86_INSTRUCTION_DEF(vinsertf32x4)
{
	x86_unimplemented(regs, "vinsertf32x4");
}

X86_INSTRUCTION_DEF(vinsertf64x4)
{
	x86_unimplemented(regs, "vinsertf64x4");
}

X86_INSTRUCTION_DEF(vinserti128)
{
	x86_unimplemented(regs, "vinserti128");
}

X86_INSTRUCTION_DEF(vinserti32x4)
{
	x86_unimplemented(regs, "vinserti32x4");
}

X86_INSTRUCTION_DEF(vinserti64x4)
{
	x86_unimplemented(regs, "vinserti64x4");
}

X86_INSTRUCTION_DEF(vinsertps)
{
	x86_unimplemented(regs, "vinsertps");
}

X86_INSTRUCTION_DEF(vlddqu)
{
	x86_unimplemented(regs, "vlddqu");
}

X86_INSTRUCTION_DEF(vldmxcsr)
{
	x86_unimplemented(regs, "vldmxcsr");
}

X86_INSTRUCTION_DEF(vmaskmovdqu)
{
	x86_unimplemented(regs, "vmaskmovdqu");
}

X86_INSTRUCTION_DEF(vmaskmovpd)
{
	x86_unimplemented(regs, "vmaskmovpd");
}

X86_INSTRUCTION_DEF(vmaskmovps)
{
	x86_unimplemented(regs, "vmaskmovps");
}

X86_INSTRUCTION_DEF(vmaxpd)
{
	x86_unimplemented(regs, "vmaxpd");
}

X86_INSTRUCTION_DEF(vmaxps)
{
	x86_unimplemented(regs, "vmaxps");
}

X86_INSTRUCTION_DEF(vmaxsd)
{
	x86_unimplemented(regs, "vmaxsd");
}

X86_INSTRUCTION_DEF(vmaxss)
{
	x86_unimplemented(regs, "vmaxss");
}

X86_INSTRUCTION_DEF(vmcall)
{
	x86_unimplemented(regs, "vmcall");
}

X86_INSTRUCTION_DEF(vmclear)
{
	x86_unimplemented(regs, "vmclear");
}

X86_INSTRUCTION_DEF(vmfunc)
{
	x86_unimplemented(regs, "vmfunc");
}

X86_INSTRUCTION_DEF(vminpd)
{
	x86_unimplemented(regs, "vminpd");
}

X86_INSTRUCTION_DEF(vminps)
{
	x86_unimplemented(regs, "vminps");
}

X86_INSTRUCTION_DEF(vminsd)
{
	x86_unimplemented(regs, "vminsd");
}

X86_INSTRUCTION_DEF(vminss)
{
	x86_unimplemented(regs, "vminss");
}

X86_INSTRUCTION_DEF(vmlaunch)
{
	x86_unimplemented(regs, "vmlaunch");
}

X86_INSTRUCTION_DEF(vmload)
{
	x86_unimplemented(regs, "vmload");
}

X86_INSTRUCTION_DEF(vmmcall)
{
	x86_unimplemented(regs, "vmmcall");
}

X86_INSTRUCTION_DEF(vmovapd)
{
	x86_unimplemented(regs, "vmovapd");
}

X86_INSTRUCTION_DEF(vmovaps)
{
	x86_unimplemented(regs, "vmovaps");
}

X86_INSTRUCTION_DEF(vmovd)
{
	x86_unimplemented(regs, "vmovd");
}

X86_INSTRUCTION_DEF(vmovddup)
{
	x86_unimplemented(regs, "vmovddup");
}

X86_INSTRUCTION_DEF(vmovdqa)
{
	x86_unimplemented(regs, "vmovdqa");
}

X86_INSTRUCTION_DEF(vmovdqa32)
{
	x86_unimplemented(regs, "vmovdqa32");
}

X86_INSTRUCTION_DEF(vmovdqa64)
{
	x86_unimplemented(regs, "vmovdqa64");
}

X86_INSTRUCTION_DEF(vmovdqu)
{
	x86_unimplemented(regs, "vmovdqu");
}

X86_INSTRUCTION_DEF(vmovdqu16)
{
	x86_unimplemented(regs, "vmovdqu16");
}

X86_INSTRUCTION_DEF(vmovdqu32)
{
	x86_unimplemented(regs, "vmovdqu32");
}

X86_INSTRUCTION_DEF(vmovdqu64)
{
	x86_unimplemented(regs, "vmovdqu64");
}

X86_INSTRUCTION_DEF(vmovdqu8)
{
	x86_unimplemented(regs, "vmovdqu8");
}

X86_INSTRUCTION_DEF(vmovhlps)
{
	x86_unimplemented(regs, "vmovhlps");
}

X86_INSTRUCTION_DEF(vmovhpd)
{
	x86_unimplemented(regs, "vmovhpd");
}

X86_INSTRUCTION_DEF(vmovhps)
{
	x86_unimplemented(regs, "vmovhps");
}

X86_INSTRUCTION_DEF(vmovlhps)
{
	x86_unimplemented(regs, "vmovlhps");
}

X86_INSTRUCTION_DEF(vmovlpd)
{
	x86_unimplemented(regs, "vmovlpd");
}

X86_INSTRUCTION_DEF(vmovlps)
{
	x86_unimplemented(regs, "vmovlps");
}

X86_INSTRUCTION_DEF(vmovmskpd)
{
	x86_unimplemented(regs, "vmovmskpd");
}

X86_INSTRUCTION_DEF(vmovmskps)
{
	x86_unimplemented(regs, "vmovmskps");
}

X86_INSTRUCTION_DEF(vmovntdq)
{
	x86_unimplemented(regs, "vmovntdq");
}

X86_INSTRUCTION_DEF(vmovntdqa)
{
	x86_unimplemented(regs, "vmovntdqa");
}

X86_INSTRUCTION_DEF(vmovntpd)
{
	x86_unimplemented(regs, "vmovntpd");
}

X86_INSTRUCTION_DEF(vmovntps)
{
	x86_unimplemented(regs, "vmovntps");
}

X86_INSTRUCTION_DEF(vmovq)
{
	x86_unimplemented(regs, "vmovq");
}

X86_INSTRUCTION_DEF(vmovsd)
{
	x86_unimplemented(regs, "vmovsd");
}

X86_INSTRUCTION_DEF(vmovshdup)
{
	x86_unimplemented(regs, "vmovshdup");
}

X86_INSTRUCTION_DEF(vmovsldup)
{
	x86_unimplemented(regs, "vmovsldup");
}

X86_INSTRUCTION_DEF(vmovss)
{
	x86_unimplemented(regs, "vmovss");
}

X86_INSTRUCTION_DEF(vmovupd)
{
	x86_unimplemented(regs, "vmovupd");
}

X86_INSTRUCTION_DEF(vmovups)
{
	x86_unimplemented(regs, "vmovups");
}

X86_INSTRUCTION_DEF(vmpsadbw)
{
	x86_unimplemented(regs, "vmpsadbw");
}

X86_INSTRUCTION_DEF(vmptrld)
{
	x86_unimplemented(regs, "vmptrld");
}

X86_INSTRUCTION_DEF(vmptrst)
{
	x86_unimplemented(regs, "vmptrst");
}

X86_INSTRUCTION_DEF(vmread)
{
	x86_unimplemented(regs, "vmread");
}

X86_INSTRUCTION_DEF(vmresume)
{
	x86_unimplemented(regs, "vmresume");
}

X86_INSTRUCTION_DEF(vmrun)
{
	x86_unimplemented(regs, "vmrun");
}

X86_INSTRUCTION_DEF(vmsave)
{
	x86_unimplemented(regs, "vmsave");
}

X86_INSTRUCTION_DEF(vmulpd)
{
	x86_unimplemented(regs, "vmulpd");
}

X86_INSTRUCTION_DEF(vmulps)
{
	x86_unimplemented(regs, "vmulps");
}

X86_INSTRUCTION_DEF(vmulsd)
{
	x86_unimplemented(regs, "vmulsd");
}

X86_INSTRUCTION_DEF(vmulss)
{
	x86_unimplemented(regs, "vmulss");
}

X86_INSTRUCTION_DEF(vmwrite)
{
	x86_unimplemented(regs, "vmwrite");
}

X86_INSTRUCTION_DEF(vmxoff)
{
	x86_unimplemented(regs, "vmxoff");
}

X86_INSTRUCTION_DEF(vmxon)
{
	x86_unimplemented(regs, "vmxon");
}

X86_INSTRUCTION_DEF(vorpd)
{
	x86_unimplemented(regs, "vorpd");
}

X86_INSTRUCTION_DEF(vorps)
{
	x86_unimplemented(regs, "vorps");
}

X86_INSTRUCTION_DEF(vpabsb)
{
	x86_unimplemented(regs, "vpabsb");
}

X86_INSTRUCTION_DEF(vpabsd)
{
	x86_unimplemented(regs, "vpabsd");
}

X86_INSTRUCTION_DEF(vpabsq)
{
	x86_unimplemented(regs, "vpabsq");
}

X86_INSTRUCTION_DEF(vpabsw)
{
	x86_unimplemented(regs, "vpabsw");
}

X86_INSTRUCTION_DEF(vpackssdw)
{
	x86_unimplemented(regs, "vpackssdw");
}

X86_INSTRUCTION_DEF(vpacksswb)
{
	x86_unimplemented(regs, "vpacksswb");
}

X86_INSTRUCTION_DEF(vpackusdw)
{
	x86_unimplemented(regs, "vpackusdw");
}

X86_INSTRUCTION_DEF(vpackuswb)
{
	x86_unimplemented(regs, "vpackuswb");
}

X86_INSTRUCTION_DEF(vpaddb)
{
	x86_unimplemented(regs, "vpaddb");
}

X86_INSTRUCTION_DEF(vpaddd)
{
	x86_unimplemented(regs, "vpaddd");
}

X86_INSTRUCTION_DEF(vpaddq)
{
	x86_unimplemented(regs, "vpaddq");
}

X86_INSTRUCTION_DEF(vpaddsb)
{
	x86_unimplemented(regs, "vpaddsb");
}

X86_INSTRUCTION_DEF(vpaddsw)
{
	x86_unimplemented(regs, "vpaddsw");
}

X86_INSTRUCTION_DEF(vpaddusb)
{
	x86_unimplemented(regs, "vpaddusb");
}

X86_INSTRUCTION_DEF(vpaddusw)
{
	x86_unimplemented(regs, "vpaddusw");
}

X86_INSTRUCTION_DEF(vpaddw)
{
	x86_unimplemented(regs, "vpaddw");
}

X86_INSTRUCTION_DEF(vpalignr)
{
	x86_unimplemented(regs, "vpalignr");
}

X86_INSTRUCTION_DEF(vpand)
{
	x86_unimplemented(regs, "vpand");
}

X86_INSTRUCTION_DEF(vpandd)
{
	x86_unimplemented(regs, "vpandd");
}

X86_INSTRUCTION_DEF(vpandn)
{
	x86_unimplemented(regs, "vpandn");
}

X86_INSTRUCTION_DEF(vpandnd)
{
	x86_unimplemented(regs, "vpandnd");
}

X86_INSTRUCTION_DEF(vpandnq)
{
	x86_unimplemented(regs, "vpandnq");
}

X86_INSTRUCTION_DEF(vpandq)
{
	x86_unimplemented(regs, "vpandq");
}

X86_INSTRUCTION_DEF(vpavgb)
{
	x86_unimplemented(regs, "vpavgb");
}

X86_INSTRUCTION_DEF(vpavgw)
{
	x86_unimplemented(regs, "vpavgw");
}

X86_INSTRUCTION_DEF(vpblendd)
{
	x86_unimplemented(regs, "vpblendd");
}

X86_INSTRUCTION_DEF(vpblendmd)
{
	x86_unimplemented(regs, "vpblendmd");
}

X86_INSTRUCTION_DEF(vpblendmq)
{
	x86_unimplemented(regs, "vpblendmq");
}

X86_INSTRUCTION_DEF(vpblendvb)
{
	x86_unimplemented(regs, "vpblendvb");
}

X86_INSTRUCTION_DEF(vpblendw)
{
	x86_unimplemented(regs, "vpblendw");
}

X86_INSTRUCTION_DEF(vpbroadcastb)
{
	x86_unimplemented(regs, "vpbroadcastb");
}

X86_INSTRUCTION_DEF(vpbroadcastd)
{
	x86_unimplemented(regs, "vpbroadcastd");
}

X86_INSTRUCTION_DEF(vpbroadcastmb2q)
{
	x86_unimplemented(regs, "vpbroadcastmb2q");
}

X86_INSTRUCTION_DEF(vpbroadcastmw2d)
{
	x86_unimplemented(regs, "vpbroadcastmw2d");
}

X86_INSTRUCTION_DEF(vpbroadcastq)
{
	x86_unimplemented(regs, "vpbroadcastq");
}

X86_INSTRUCTION_DEF(vpbroadcastw)
{
	x86_unimplemented(regs, "vpbroadcastw");
}

X86_INSTRUCTION_DEF(vpclmulqdq)
{
	x86_unimplemented(regs, "vpclmulqdq");
}

X86_INSTRUCTION_DEF(vpcmov)
{
	x86_unimplemented(regs, "vpcmov");
}

X86_INSTRUCTION_DEF(vpcmp)
{
	x86_unimplemented(regs, "vpcmp");
}

X86_INSTRUCTION_DEF(vpcmpd)
{
	x86_unimplemented(regs, "vpcmpd");
}

X86_INSTRUCTION_DEF(vpcmpeqb)
{
	x86_unimplemented(regs, "vpcmpeqb");
}

X86_INSTRUCTION_DEF(vpcmpeqd)
{
	x86_unimplemented(regs, "vpcmpeqd");
}

X86_INSTRUCTION_DEF(vpcmpeqq)
{
	x86_unimplemented(regs, "vpcmpeqq");
}

X86_INSTRUCTION_DEF(vpcmpeqw)
{
	x86_unimplemented(regs, "vpcmpeqw");
}

X86_INSTRUCTION_DEF(vpcmpestri)
{
	x86_unimplemented(regs, "vpcmpestri");
}

X86_INSTRUCTION_DEF(vpcmpestrm)
{
	x86_unimplemented(regs, "vpcmpestrm");
}

X86_INSTRUCTION_DEF(vpcmpgtb)
{
	x86_unimplemented(regs, "vpcmpgtb");
}

X86_INSTRUCTION_DEF(vpcmpgtd)
{
	x86_unimplemented(regs, "vpcmpgtd");
}

X86_INSTRUCTION_DEF(vpcmpgtq)
{
	x86_unimplemented(regs, "vpcmpgtq");
}

X86_INSTRUCTION_DEF(vpcmpgtw)
{
	x86_unimplemented(regs, "vpcmpgtw");
}

X86_INSTRUCTION_DEF(vpcmpistri)
{
	x86_unimplemented(regs, "vpcmpistri");
}

X86_INSTRUCTION_DEF(vpcmpistrm)
{
	x86_unimplemented(regs, "vpcmpistrm");
}

X86_INSTRUCTION_DEF(vpcmpq)
{
	x86_unimplemented(regs, "vpcmpq");
}

X86_INSTRUCTION_DEF(vpcmpud)
{
	x86_unimplemented(regs, "vpcmpud");
}

X86_INSTRUCTION_DEF(vpcmpuq)
{
	x86_unimplemented(regs, "vpcmpuq");
}

X86_INSTRUCTION_DEF(vpcomb)
{
	x86_unimplemented(regs, "vpcomb");
}

X86_INSTRUCTION_DEF(vpcomd)
{
	x86_unimplemented(regs, "vpcomd");
}

X86_INSTRUCTION_DEF(vpcomq)
{
	x86_unimplemented(regs, "vpcomq");
}

X86_INSTRUCTION_DEF(vpcomub)
{
	x86_unimplemented(regs, "vpcomub");
}

X86_INSTRUCTION_DEF(vpcomud)
{
	x86_unimplemented(regs, "vpcomud");
}

X86_INSTRUCTION_DEF(vpcomuq)
{
	x86_unimplemented(regs, "vpcomuq");
}

X86_INSTRUCTION_DEF(vpcomuw)
{
	x86_unimplemented(regs, "vpcomuw");
}

X86_INSTRUCTION_DEF(vpcomw)
{
	x86_unimplemented(regs, "vpcomw");
}

X86_INSTRUCTION_DEF(vpconflictd)
{
	x86_unimplemented(regs, "vpconflictd");
}

X86_INSTRUCTION_DEF(vpconflictq)
{
	x86_unimplemented(regs, "vpconflictq");
}

X86_INSTRUCTION_DEF(vperm2f128)
{
	x86_unimplemented(regs, "vperm2f128");
}

X86_INSTRUCTION_DEF(vperm2i128)
{
	x86_unimplemented(regs, "vperm2i128");
}

X86_INSTRUCTION_DEF(vpermd)
{
	x86_unimplemented(regs, "vpermd");
}

X86_INSTRUCTION_DEF(vpermi2d)
{
	x86_unimplemented(regs, "vpermi2d");
}

X86_INSTRUCTION_DEF(vpermi2pd)
{
	x86_unimplemented(regs, "vpermi2pd");
}

X86_INSTRUCTION_DEF(vpermi2ps)
{
	x86_unimplemented(regs, "vpermi2ps");
}

X86_INSTRUCTION_DEF(vpermi2q)
{
	x86_unimplemented(regs, "vpermi2q");
}

X86_INSTRUCTION_DEF(vpermil2pd)
{
	x86_unimplemented(regs, "vpermil2pd");
}

X86_INSTRUCTION_DEF(vpermil2ps)
{
	x86_unimplemented(regs, "vpermil2ps");
}

X86_INSTRUCTION_DEF(vpermilpd)
{
	x86_unimplemented(regs, "vpermilpd");
}

X86_INSTRUCTION_DEF(vpermilps)
{
	x86_unimplemented(regs, "vpermilps");
}

X86_INSTRUCTION_DEF(vpermpd)
{
	x86_unimplemented(regs, "vpermpd");
}

X86_INSTRUCTION_DEF(vpermps)
{
	x86_unimplemented(regs, "vpermps");
}

X86_INSTRUCTION_DEF(vpermq)
{
	x86_unimplemented(regs, "vpermq");
}

X86_INSTRUCTION_DEF(vpermt2d)
{
	x86_unimplemented(regs, "vpermt2d");
}

X86_INSTRUCTION_DEF(vpermt2pd)
{
	x86_unimplemented(regs, "vpermt2pd");
}

X86_INSTRUCTION_DEF(vpermt2ps)
{
	x86_unimplemented(regs, "vpermt2ps");
}

X86_INSTRUCTION_DEF(vpermt2q)
{
	x86_unimplemented(regs, "vpermt2q");
}

X86_INSTRUCTION_DEF(vpextrb)
{
	x86_unimplemented(regs, "vpextrb");
}

X86_INSTRUCTION_DEF(vpextrd)
{
	x86_unimplemented(regs, "vpextrd");
}

X86_INSTRUCTION_DEF(vpextrq)
{
	x86_unimplemented(regs, "vpextrq");
}

X86_INSTRUCTION_DEF(vpextrw)
{
	x86_unimplemented(regs, "vpextrw");
}

X86_INSTRUCTION_DEF(vpgatherdd)
{
	x86_unimplemented(regs, "vpgatherdd");
}

X86_INSTRUCTION_DEF(vpgatherdq)
{
	x86_unimplemented(regs, "vpgatherdq");
}

X86_INSTRUCTION_DEF(vpgatherqd)
{
	x86_unimplemented(regs, "vpgatherqd");
}

X86_INSTRUCTION_DEF(vpgatherqq)
{
	x86_unimplemented(regs, "vpgatherqq");
}

X86_INSTRUCTION_DEF(vphaddbd)
{
	x86_unimplemented(regs, "vphaddbd");
}

X86_INSTRUCTION_DEF(vphaddbq)
{
	x86_unimplemented(regs, "vphaddbq");
}

X86_INSTRUCTION_DEF(vphaddbw)
{
	x86_unimplemented(regs, "vphaddbw");
}

X86_INSTRUCTION_DEF(vphaddd)
{
	x86_unimplemented(regs, "vphaddd");
}

X86_INSTRUCTION_DEF(vphadddq)
{
	x86_unimplemented(regs, "vphadddq");
}

X86_INSTRUCTION_DEF(vphaddsw)
{
	x86_unimplemented(regs, "vphaddsw");
}

X86_INSTRUCTION_DEF(vphaddubd)
{
	x86_unimplemented(regs, "vphaddubd");
}

X86_INSTRUCTION_DEF(vphaddubq)
{
	x86_unimplemented(regs, "vphaddubq");
}

X86_INSTRUCTION_DEF(vphaddubw)
{
	x86_unimplemented(regs, "vphaddubw");
}

X86_INSTRUCTION_DEF(vphaddudq)
{
	x86_unimplemented(regs, "vphaddudq");
}

X86_INSTRUCTION_DEF(vphadduwd)
{
	x86_unimplemented(regs, "vphadduwd");
}

X86_INSTRUCTION_DEF(vphadduwq)
{
	x86_unimplemented(regs, "vphadduwq");
}

X86_INSTRUCTION_DEF(vphaddw)
{
	x86_unimplemented(regs, "vphaddw");
}

X86_INSTRUCTION_DEF(vphaddwd)
{
	x86_unimplemented(regs, "vphaddwd");
}

X86_INSTRUCTION_DEF(vphaddwq)
{
	x86_unimplemented(regs, "vphaddwq");
}

X86_INSTRUCTION_DEF(vphminposuw)
{
	x86_unimplemented(regs, "vphminposuw");
}

X86_INSTRUCTION_DEF(vphsubbw)
{
	x86_unimplemented(regs, "vphsubbw");
}

X86_INSTRUCTION_DEF(vphsubd)
{
	x86_unimplemented(regs, "vphsubd");
}

X86_INSTRUCTION_DEF(vphsubdq)
{
	x86_unimplemented(regs, "vphsubdq");
}

X86_INSTRUCTION_DEF(vphsubsw)
{
	x86_unimplemented(regs, "vphsubsw");
}

X86_INSTRUCTION_DEF(vphsubw)
{
	x86_unimplemented(regs, "vphsubw");
}

X86_INSTRUCTION_DEF(vphsubwd)
{
	x86_unimplemented(regs, "vphsubwd");
}

X86_INSTRUCTION_DEF(vpinsrb)
{
	x86_unimplemented(regs, "vpinsrb");
}

X86_INSTRUCTION_DEF(vpinsrd)
{
	x86_unimplemented(regs, "vpinsrd");
}

X86_INSTRUCTION_DEF(vpinsrq)
{
	x86_unimplemented(regs, "vpinsrq");
}

X86_INSTRUCTION_DEF(vpinsrw)
{
	x86_unimplemented(regs, "vpinsrw");
}

X86_INSTRUCTION_DEF(vplzcntd)
{
	x86_unimplemented(regs, "vplzcntd");
}

X86_INSTRUCTION_DEF(vplzcntq)
{
	x86_unimplemented(regs, "vplzcntq");
}

X86_INSTRUCTION_DEF(vpmacsdd)
{
	x86_unimplemented(regs, "vpmacsdd");
}

X86_INSTRUCTION_DEF(vpmacsdqh)
{
	x86_unimplemented(regs, "vpmacsdqh");
}

X86_INSTRUCTION_DEF(vpmacsdql)
{
	x86_unimplemented(regs, "vpmacsdql");
}

X86_INSTRUCTION_DEF(vpmacssdd)
{
	x86_unimplemented(regs, "vpmacssdd");
}

X86_INSTRUCTION_DEF(vpmacssdqh)
{
	x86_unimplemented(regs, "vpmacssdqh");
}

X86_INSTRUCTION_DEF(vpmacssdql)
{
	x86_unimplemented(regs, "vpmacssdql");
}

X86_INSTRUCTION_DEF(vpmacsswd)
{
	x86_unimplemented(regs, "vpmacsswd");
}

X86_INSTRUCTION_DEF(vpmacssww)
{
	x86_unimplemented(regs, "vpmacssww");
}

X86_INSTRUCTION_DEF(vpmacswd)
{
	x86_unimplemented(regs, "vpmacswd");
}

X86_INSTRUCTION_DEF(vpmacsww)
{
	x86_unimplemented(regs, "vpmacsww");
}

X86_INSTRUCTION_DEF(vpmadcsswd)
{
	x86_unimplemented(regs, "vpmadcsswd");
}

X86_INSTRUCTION_DEF(vpmadcswd)
{
	x86_unimplemented(regs, "vpmadcswd");
}

X86_INSTRUCTION_DEF(vpmaddubsw)
{
	x86_unimplemented(regs, "vpmaddubsw");
}

X86_INSTRUCTION_DEF(vpmaddwd)
{
	x86_unimplemented(regs, "vpmaddwd");
}

X86_INSTRUCTION_DEF(vpmaskmovd)
{
	x86_unimplemented(regs, "vpmaskmovd");
}

X86_INSTRUCTION_DEF(vpmaskmovq)
{
	x86_unimplemented(regs, "vpmaskmovq");
}

X86_INSTRUCTION_DEF(vpmaxsb)
{
	x86_unimplemented(regs, "vpmaxsb");
}

X86_INSTRUCTION_DEF(vpmaxsd)
{
	x86_unimplemented(regs, "vpmaxsd");
}

X86_INSTRUCTION_DEF(vpmaxsq)
{
	x86_unimplemented(regs, "vpmaxsq");
}

X86_INSTRUCTION_DEF(vpmaxsw)
{
	x86_unimplemented(regs, "vpmaxsw");
}

X86_INSTRUCTION_DEF(vpmaxub)
{
	x86_unimplemented(regs, "vpmaxub");
}

X86_INSTRUCTION_DEF(vpmaxud)
{
	x86_unimplemented(regs, "vpmaxud");
}

X86_INSTRUCTION_DEF(vpmaxuq)
{
	x86_unimplemented(regs, "vpmaxuq");
}

X86_INSTRUCTION_DEF(vpmaxuw)
{
	x86_unimplemented(regs, "vpmaxuw");
}

X86_INSTRUCTION_DEF(vpminsb)
{
	x86_unimplemented(regs, "vpminsb");
}

X86_INSTRUCTION_DEF(vpminsd)
{
	x86_unimplemented(regs, "vpminsd");
}

X86_INSTRUCTION_DEF(vpminsq)
{
	x86_unimplemented(regs, "vpminsq");
}

X86_INSTRUCTION_DEF(vpminsw)
{
	x86_unimplemented(regs, "vpminsw");
}

X86_INSTRUCTION_DEF(vpminub)
{
	x86_unimplemented(regs, "vpminub");
}

X86_INSTRUCTION_DEF(vpminud)
{
	x86_unimplemented(regs, "vpminud");
}

X86_INSTRUCTION_DEF(vpminuq)
{
	x86_unimplemented(regs, "vpminuq");
}

X86_INSTRUCTION_DEF(vpminuw)
{
	x86_unimplemented(regs, "vpminuw");
}

X86_INSTRUCTION_DEF(vpmovdb)
{
	x86_unimplemented(regs, "vpmovdb");
}

X86_INSTRUCTION_DEF(vpmovdw)
{
	x86_unimplemented(regs, "vpmovdw");
}

X86_INSTRUCTION_DEF(vpmovmskb)
{
	x86_unimplemented(regs, "vpmovmskb");
}

X86_INSTRUCTION_DEF(vpmovqb)
{
	x86_unimplemented(regs, "vpmovqb");
}

X86_INSTRUCTION_DEF(vpmovqd)
{
	x86_unimplemented(regs, "vpmovqd");
}

X86_INSTRUCTION_DEF(vpmovqw)
{
	x86_unimplemented(regs, "vpmovqw");
}

X86_INSTRUCTION_DEF(vpmovsdb)
{
	x86_unimplemented(regs, "vpmovsdb");
}

X86_INSTRUCTION_DEF(vpmovsdw)
{
	x86_unimplemented(regs, "vpmovsdw");
}

X86_INSTRUCTION_DEF(vpmovsqb)
{
	x86_unimplemented(regs, "vpmovsqb");
}

X86_INSTRUCTION_DEF(vpmovsqd)
{
	x86_unimplemented(regs, "vpmovsqd");
}

X86_INSTRUCTION_DEF(vpmovsqw)
{
	x86_unimplemented(regs, "vpmovsqw");
}

X86_INSTRUCTION_DEF(vpmovsxbd)
{
	x86_unimplemented(regs, "vpmovsxbd");
}

X86_INSTRUCTION_DEF(vpmovsxbq)
{
	x86_unimplemented(regs, "vpmovsxbq");
}

X86_INSTRUCTION_DEF(vpmovsxbw)
{
	x86_unimplemented(regs, "vpmovsxbw");
}

X86_INSTRUCTION_DEF(vpmovsxdq)
{
	x86_unimplemented(regs, "vpmovsxdq");
}

X86_INSTRUCTION_DEF(vpmovsxwd)
{
	x86_unimplemented(regs, "vpmovsxwd");
}

X86_INSTRUCTION_DEF(vpmovsxwq)
{
	x86_unimplemented(regs, "vpmovsxwq");
}

X86_INSTRUCTION_DEF(vpmovusdb)
{
	x86_unimplemented(regs, "vpmovusdb");
}

X86_INSTRUCTION_DEF(vpmovusdw)
{
	x86_unimplemented(regs, "vpmovusdw");
}

X86_INSTRUCTION_DEF(vpmovusqb)
{
	x86_unimplemented(regs, "vpmovusqb");
}

X86_INSTRUCTION_DEF(vpmovusqd)
{
	x86_unimplemented(regs, "vpmovusqd");
}

X86_INSTRUCTION_DEF(vpmovusqw)
{
	x86_unimplemented(regs, "vpmovusqw");
}

X86_INSTRUCTION_DEF(vpmovzxbd)
{
	x86_unimplemented(regs, "vpmovzxbd");
}

X86_INSTRUCTION_DEF(vpmovzxbq)
{
	x86_unimplemented(regs, "vpmovzxbq");
}

X86_INSTRUCTION_DEF(vpmovzxbw)
{
	x86_unimplemented(regs, "vpmovzxbw");
}

X86_INSTRUCTION_DEF(vpmovzxdq)
{
	x86_unimplemented(regs, "vpmovzxdq");
}

X86_INSTRUCTION_DEF(vpmovzxwd)
{
	x86_unimplemented(regs, "vpmovzxwd");
}

X86_INSTRUCTION_DEF(vpmovzxwq)
{
	x86_unimplemented(regs, "vpmovzxwq");
}

X86_INSTRUCTION_DEF(vpmuldq)
{
	x86_unimplemented(regs, "vpmuldq");
}

X86_INSTRUCTION_DEF(vpmulhrsw)
{
	x86_unimplemented(regs, "vpmulhrsw");
}

X86_INSTRUCTION_DEF(vpmulhuw)
{
	x86_unimplemented(regs, "vpmulhuw");
}

X86_INSTRUCTION_DEF(vpmulhw)
{
	x86_unimplemented(regs, "vpmulhw");
}

X86_INSTRUCTION_DEF(vpmulld)
{
	x86_unimplemented(regs, "vpmulld");
}

X86_INSTRUCTION_DEF(vpmullw)
{
	x86_unimplemented(regs, "vpmullw");
}

X86_INSTRUCTION_DEF(vpmuludq)
{
	x86_unimplemented(regs, "vpmuludq");
}

X86_INSTRUCTION_DEF(vpor)
{
	x86_unimplemented(regs, "vpor");
}

X86_INSTRUCTION_DEF(vpord)
{
	x86_unimplemented(regs, "vpord");
}

X86_INSTRUCTION_DEF(vporq)
{
	x86_unimplemented(regs, "vporq");
}

X86_INSTRUCTION_DEF(vpperm)
{
	x86_unimplemented(regs, "vpperm");
}

X86_INSTRUCTION_DEF(vprotb)
{
	x86_unimplemented(regs, "vprotb");
}

X86_INSTRUCTION_DEF(vprotd)
{
	x86_unimplemented(regs, "vprotd");
}

X86_INSTRUCTION_DEF(vprotq)
{
	x86_unimplemented(regs, "vprotq");
}

X86_INSTRUCTION_DEF(vprotw)
{
	x86_unimplemented(regs, "vprotw");
}

X86_INSTRUCTION_DEF(vpsadbw)
{
	x86_unimplemented(regs, "vpsadbw");
}

X86_INSTRUCTION_DEF(vpscatterdd)
{
	x86_unimplemented(regs, "vpscatterdd");
}

X86_INSTRUCTION_DEF(vpscatterdq)
{
	x86_unimplemented(regs, "vpscatterdq");
}

X86_INSTRUCTION_DEF(vpscatterqd)
{
	x86_unimplemented(regs, "vpscatterqd");
}

X86_INSTRUCTION_DEF(vpscatterqq)
{
	x86_unimplemented(regs, "vpscatterqq");
}

X86_INSTRUCTION_DEF(vpshab)
{
	x86_unimplemented(regs, "vpshab");
}

X86_INSTRUCTION_DEF(vpshad)
{
	x86_unimplemented(regs, "vpshad");
}

X86_INSTRUCTION_DEF(vpshaq)
{
	x86_unimplemented(regs, "vpshaq");
}

X86_INSTRUCTION_DEF(vpshaw)
{
	x86_unimplemented(regs, "vpshaw");
}

X86_INSTRUCTION_DEF(vpshlb)
{
	x86_unimplemented(regs, "vpshlb");
}

X86_INSTRUCTION_DEF(vpshld)
{
	x86_unimplemented(regs, "vpshld");
}

X86_INSTRUCTION_DEF(vpshlq)
{
	x86_unimplemented(regs, "vpshlq");
}

X86_INSTRUCTION_DEF(vpshlw)
{
	x86_unimplemented(regs, "vpshlw");
}

X86_INSTRUCTION_DEF(vpshufb)
{
	x86_unimplemented(regs, "vpshufb");
}

X86_INSTRUCTION_DEF(vpshufd)
{
	x86_unimplemented(regs, "vpshufd");
}

X86_INSTRUCTION_DEF(vpshufhw)
{
	x86_unimplemented(regs, "vpshufhw");
}

X86_INSTRUCTION_DEF(vpshuflw)
{
	x86_unimplemented(regs, "vpshuflw");
}

X86_INSTRUCTION_DEF(vpsignb)
{
	x86_unimplemented(regs, "vpsignb");
}

X86_INSTRUCTION_DEF(vpsignd)
{
	x86_unimplemented(regs, "vpsignd");
}

X86_INSTRUCTION_DEF(vpsignw)
{
	x86_unimplemented(regs, "vpsignw");
}

X86_INSTRUCTION_DEF(vpslld)
{
	x86_unimplemented(regs, "vpslld");
}

X86_INSTRUCTION_DEF(vpslldq)
{
	x86_unimplemented(regs, "vpslldq");
}

X86_INSTRUCTION_DEF(vpsllq)
{
	x86_unimplemented(regs, "vpsllq");
}

X86_INSTRUCTION_DEF(vpsllvd)
{
	x86_unimplemented(regs, "vpsllvd");
}

X86_INSTRUCTION_DEF(vpsllvq)
{
	x86_unimplemented(regs, "vpsllvq");
}

X86_INSTRUCTION_DEF(vpsllw)
{
	x86_unimplemented(regs, "vpsllw");
}

X86_INSTRUCTION_DEF(vpsrad)
{
	x86_unimplemented(regs, "vpsrad");
}

X86_INSTRUCTION_DEF(vpsraq)
{
	x86_unimplemented(regs, "vpsraq");
}

X86_INSTRUCTION_DEF(vpsravd)
{
	x86_unimplemented(regs, "vpsravd");
}

X86_INSTRUCTION_DEF(vpsravq)
{
	x86_unimplemented(regs, "vpsravq");
}

X86_INSTRUCTION_DEF(vpsraw)
{
	x86_unimplemented(regs, "vpsraw");
}

X86_INSTRUCTION_DEF(vpsrld)
{
	x86_unimplemented(regs, "vpsrld");
}

X86_INSTRUCTION_DEF(vpsrldq)
{
	x86_unimplemented(regs, "vpsrldq");
}

X86_INSTRUCTION_DEF(vpsrlq)
{
	x86_unimplemented(regs, "vpsrlq");
}

X86_INSTRUCTION_DEF(vpsrlvd)
{
	x86_unimplemented(regs, "vpsrlvd");
}

X86_INSTRUCTION_DEF(vpsrlvq)
{
	x86_unimplemented(regs, "vpsrlvq");
}

X86_INSTRUCTION_DEF(vpsrlw)
{
	x86_unimplemented(regs, "vpsrlw");
}

X86_INSTRUCTION_DEF(vpsubb)
{
	x86_unimplemented(regs, "vpsubb");
}

X86_INSTRUCTION_DEF(vpsubd)
{
	x86_unimplemented(regs, "vpsubd");
}

X86_INSTRUCTION_DEF(vpsubq)
{
	x86_unimplemented(regs, "vpsubq");
}

X86_INSTRUCTION_DEF(vpsubsb)
{
	x86_unimplemented(regs, "vpsubsb");
}

X86_INSTRUCTION_DEF(vpsubsw)
{
	x86_unimplemented(regs, "vpsubsw");
}

X86_INSTRUCTION_DEF(vpsubusb)
{
	x86_unimplemented(regs, "vpsubusb");
}

X86_INSTRUCTION_DEF(vpsubusw)
{
	x86_unimplemented(regs, "vpsubusw");
}

X86_INSTRUCTION_DEF(vpsubw)
{
	x86_unimplemented(regs, "vpsubw");
}

X86_INSTRUCTION_DEF(vptest)
{
	x86_unimplemented(regs, "vptest");
}

X86_INSTRUCTION_DEF(vptestmd)
{
	x86_unimplemented(regs, "vptestmd");
}

X86_INSTRUCTION_DEF(vptestmq)
{
	x86_unimplemented(regs, "vptestmq");
}

X86_INSTRUCTION_DEF(vptestnmd)
{
	x86_unimplemented(regs, "vptestnmd");
}

X86_INSTRUCTION_DEF(vptestnmq)
{
	x86_unimplemented(regs, "vptestnmq");
}

X86_INSTRUCTION_DEF(vpunpckhbw)
{
	x86_unimplemented(regs, "vpunpckhbw");
}

X86_INSTRUCTION_DEF(vpunpckhdq)
{
	x86_unimplemented(regs, "vpunpckhdq");
}

X86_INSTRUCTION_DEF(vpunpckhqdq)
{
	x86_unimplemented(regs, "vpunpckhqdq");
}

X86_INSTRUCTION_DEF(vpunpckhwd)
{
	x86_unimplemented(regs, "vpunpckhwd");
}

X86_INSTRUCTION_DEF(vpunpcklbw)
{
	x86_unimplemented(regs, "vpunpcklbw");
}

X86_INSTRUCTION_DEF(vpunpckldq)
{
	x86_unimplemented(regs, "vpunpckldq");
}

X86_INSTRUCTION_DEF(vpunpcklqdq)
{
	x86_unimplemented(regs, "vpunpcklqdq");
}

X86_INSTRUCTION_DEF(vpunpcklwd)
{
	x86_unimplemented(regs, "vpunpcklwd");
}

X86_INSTRUCTION_DEF(vpxor)
{
	x86_unimplemented(regs, "vpxor");
}

X86_INSTRUCTION_DEF(vpxord)
{
	x86_unimplemented(regs, "vpxord");
}

X86_INSTRUCTION_DEF(vpxorq)
{
	x86_unimplemented(regs, "vpxorq");
}

X86_INSTRUCTION_DEF(vrcp14pd)
{
	x86_unimplemented(regs, "vrcp14pd");
}

X86_INSTRUCTION_DEF(vrcp14ps)
{
	x86_unimplemented(regs, "vrcp14ps");
}

X86_INSTRUCTION_DEF(vrcp14sd)
{
	x86_unimplemented(regs, "vrcp14sd");
}

X86_INSTRUCTION_DEF(vrcp14ss)
{
	x86_unimplemented(regs, "vrcp14ss");
}

X86_INSTRUCTION_DEF(vrcp28pd)
{
	x86_unimplemented(regs, "vrcp28pd");
}

X86_INSTRUCTION_DEF(vrcp28ps)
{
	x86_unimplemented(regs, "vrcp28ps");
}

X86_INSTRUCTION_DEF(vrcp28sd)
{
	x86_unimplemented(regs, "vrcp28sd");
}

X86_INSTRUCTION_DEF(vrcp28ss)
{
	x86_unimplemented(regs, "vrcp28ss");
}

X86_INSTRUCTION_DEF(vrcpps)
{
	x86_unimplemented(regs, "vrcpps");
}

X86_INSTRUCTION_DEF(vrcpss)
{
	x86_unimplemented(regs, "vrcpss");
}

X86_INSTRUCTION_DEF(vrndscalepd)
{
	x86_unimplemented(regs, "vrndscalepd");
}

X86_INSTRUCTION_DEF(vrndscaleps)
{
	x86_unimplemented(regs, "vrndscaleps");
}

X86_INSTRUCTION_DEF(vrndscalesd)
{
	x86_unimplemented(regs, "vrndscalesd");
}

X86_INSTRUCTION_DEF(vrndscaless)
{
	x86_unimplemented(regs, "vrndscaless");
}

X86_INSTRUCTION_DEF(vroundpd)
{
	x86_unimplemented(regs, "vroundpd");
}

X86_INSTRUCTION_DEF(vroundps)
{
	x86_unimplemented(regs, "vroundps");
}

X86_INSTRUCTION_DEF(vroundsd)
{
	x86_unimplemented(regs, "vroundsd");
}

X86_INSTRUCTION_DEF(vroundss)
{
	x86_unimplemented(regs, "vroundss");
}

X86_INSTRUCTION_DEF(vrsqrt14pd)
{
	x86_unimplemented(regs, "vrsqrt14pd");
}

X86_INSTRUCTION_DEF(vrsqrt14ps)
{
	x86_unimplemented(regs, "vrsqrt14ps");
}

X86_INSTRUCTION_DEF(vrsqrt14sd)
{
	x86_unimplemented(regs, "vrsqrt14sd");
}

X86_INSTRUCTION_DEF(vrsqrt14ss)
{
	x86_unimplemented(regs, "vrsqrt14ss");
}

X86_INSTRUCTION_DEF(vrsqrt28pd)
{
	x86_unimplemented(regs, "vrsqrt28pd");
}

X86_INSTRUCTION_DEF(vrsqrt28ps)
{
	x86_unimplemented(regs, "vrsqrt28ps");
}

X86_INSTRUCTION_DEF(vrsqrt28sd)
{
	x86_unimplemented(regs, "vrsqrt28sd");
}

X86_INSTRUCTION_DEF(vrsqrt28ss)
{
	x86_unimplemented(regs, "vrsqrt28ss");
}

X86_INSTRUCTION_DEF(vrsqrtps)
{
	x86_unimplemented(regs, "vrsqrtps");
}

X86_INSTRUCTION_DEF(vrsqrtss)
{
	x86_unimplemented(regs, "vrsqrtss");
}

X86_INSTRUCTION_DEF(vscatterdpd)
{
	x86_unimplemented(regs, "vscatterdpd");
}

X86_INSTRUCTION_DEF(vscatterdps)
{
	x86_unimplemented(regs, "vscatterdps");
}

X86_INSTRUCTION_DEF(vscatterpf0dpd)
{
	x86_unimplemented(regs, "vscatterpf0dpd");
}

X86_INSTRUCTION_DEF(vscatterpf0dps)
{
	x86_unimplemented(regs, "vscatterpf0dps");
}

X86_INSTRUCTION_DEF(vscatterpf0qpd)
{
	x86_unimplemented(regs, "vscatterpf0qpd");
}

X86_INSTRUCTION_DEF(vscatterpf0qps)
{
	x86_unimplemented(regs, "vscatterpf0qps");
}

X86_INSTRUCTION_DEF(vscatterpf1dpd)
{
	x86_unimplemented(regs, "vscatterpf1dpd");
}

X86_INSTRUCTION_DEF(vscatterpf1dps)
{
	x86_unimplemented(regs, "vscatterpf1dps");
}

X86_INSTRUCTION_DEF(vscatterpf1qpd)
{
	x86_unimplemented(regs, "vscatterpf1qpd");
}

X86_INSTRUCTION_DEF(vscatterpf1qps)
{
	x86_unimplemented(regs, "vscatterpf1qps");
}

X86_INSTRUCTION_DEF(vscatterqpd)
{
	x86_unimplemented(regs, "vscatterqpd");
}

X86_INSTRUCTION_DEF(vscatterqps)
{
	x86_unimplemented(regs, "vscatterqps");
}

X86_INSTRUCTION_DEF(vshufpd)
{
	x86_unimplemented(regs, "vshufpd");
}

X86_INSTRUCTION_DEF(vshufps)
{
	x86_unimplemented(regs, "vshufps");
}

X86_INSTRUCTION_DEF(vsqrtpd)
{
	x86_unimplemented(regs, "vsqrtpd");
}

X86_INSTRUCTION_DEF(vsqrtps)
{
	x86_unimplemented(regs, "vsqrtps");
}

X86_INSTRUCTION_DEF(vsqrtsd)
{
	x86_unimplemented(regs, "vsqrtsd");
}

X86_INSTRUCTION_DEF(vsqrtss)
{
	x86_unimplemented(regs, "vsqrtss");
}

X86_INSTRUCTION_DEF(vstmxcsr)
{
	x86_unimplemented(regs, "vstmxcsr");
}

X86_INSTRUCTION_DEF(vsubpd)
{
	x86_unimplemented(regs, "vsubpd");
}

X86_INSTRUCTION_DEF(vsubps)
{
	x86_unimplemented(regs, "vsubps");
}

X86_INSTRUCTION_DEF(vsubsd)
{
	x86_unimplemented(regs, "vsubsd");
}

X86_INSTRUCTION_DEF(vsubss)
{
	x86_unimplemented(regs, "vsubss");
}

X86_INSTRUCTION_DEF(vtestpd)
{
	x86_unimplemented(regs, "vtestpd");
}

X86_INSTRUCTION_DEF(vtestps)
{
	x86_unimplemented(regs, "vtestps");
}

X86_INSTRUCTION_DEF(vucomisd)
{
	x86_unimplemented(regs, "vucomisd");
}

X86_INSTRUCTION_DEF(vucomiss)
{
	x86_unimplemented(regs, "vucomiss");
}

X86_INSTRUCTION_DEF(vunpckhpd)
{
	x86_unimplemented(regs, "vunpckhpd");
}

X86_INSTRUCTION_DEF(vunpckhps)
{
	x86_unimplemented(regs, "vunpckhps");
}

X86_INSTRUCTION_DEF(vunpcklpd)
{
	x86_unimplemented(regs, "vunpcklpd");
}

X86_INSTRUCTION_DEF(vunpcklps)
{
	x86_unimplemented(regs, "vunpcklps");
}

X86_INSTRUCTION_DEF(vxorpd)
{
	x86_unimplemented(regs, "vxorpd");
}

X86_INSTRUCTION_DEF(vxorps)
{
	x86_unimplemented(regs, "vxorps");
}

X86_INSTRUCTION_DEF(vzeroall)
{
	x86_unimplemented(regs, "vzeroall");
}

X86_INSTRUCTION_DEF(vzeroupper)
{
	x86_unimplemented(regs, "vzeroupper");
}

X86_INSTRUCTION_DEF(wait)
{
	x86_unimplemented(regs, "wait");
}

X86_INSTRUCTION_DEF(wbinvd)
{
	x86_unimplemented(regs, "wbinvd");
}

X86_INSTRUCTION_DEF(wrfsbase)
{
	x86_unimplemented(regs, "wrfsbase");
}

X86_INSTRUCTION_DEF(wrgsbase)
{
	x86_unimplemented(regs, "wrgsbase");
}

X86_INSTRUCTION_DEF(wrmsr)
{
	x86_unimplemented(regs, "wrmsr");
}

X86_INSTRUCTION_DEF(xabort)
{
	x86_unimplemented(regs, "xabort");
}

X86_INSTRUCTION_DEF(xacquire)
{
	x86_unimplemented(regs, "xacquire");
}

X86_INSTRUCTION_DEF(xadd)
{
	x86_unimplemented(regs, "xadd");
}

X86_INSTRUCTION_DEF(xbegin)
{
	x86_unimplemented(regs, "xbegin");
}

X86_INSTRUCTION_DEF(xchg)
{
	x86_unimplemented(regs, "xchg");
}

X86_INSTRUCTION_DEF(xcryptcbc)
{
	x86_unimplemented(regs, "xcryptcbc");
}

X86_INSTRUCTION_DEF(xcryptcfb)
{
	x86_unimplemented(regs, "xcryptcfb");
}

X86_INSTRUCTION_DEF(xcryptctr)
{
	x86_unimplemented(regs, "xcryptctr");
}

X86_INSTRUCTION_DEF(xcryptecb)
{
	x86_unimplemented(regs, "xcryptecb");
}

X86_INSTRUCTION_DEF(xcryptofb)
{
	x86_unimplemented(regs, "xcryptofb");
}

X86_INSTRUCTION_DEF(xend)
{
	x86_unimplemented(regs, "xend");
}

X86_INSTRUCTION_DEF(xgetbv)
{
	x86_unimplemented(regs, "xgetbv");
}

X86_INSTRUCTION_DEF(xlatb)
{
	x86_unimplemented(regs, "xlatb");
}

X86_INSTRUCTION_DEF(xor)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t result = x86_logical_operator(regs, rflags, inst, [](uint64_t left, uint64_t right) { return left ^ right; });
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(xorpd)
{
	x86_unimplemented(regs, "xorpd");
}

X86_INSTRUCTION_DEF(xorps)
{
	x86_unimplemented(regs, "xorps");
}

X86_INSTRUCTION_DEF(xrelease)
{
	x86_unimplemented(regs, "xrelease");
}

X86_INSTRUCTION_DEF(xrstor)
{
	x86_unimplemented(regs, "xrstor");
}

X86_INSTRUCTION_DEF(xrstor64)
{
	x86_unimplemented(regs, "xrstor64");
}

X86_INSTRUCTION_DEF(xsave)
{
	x86_unimplemented(regs, "xsave");
}

X86_INSTRUCTION_DEF(xsave64)
{
	x86_unimplemented(regs, "xsave64");
}

X86_INSTRUCTION_DEF(xsaveopt)
{
	x86_unimplemented(regs, "xsaveopt");
}

X86_INSTRUCTION_DEF(xsaveopt64)
{
	x86_unimplemented(regs, "xsaveopt64");
}

X86_INSTRUCTION_DEF(xsetbv)
{
	x86_unimplemented(regs, "xsetbv");
}

X86_INSTRUCTION_DEF(xsha1)
{
	x86_unimplemented(regs, "xsha1");
}

X86_INSTRUCTION_DEF(xsha256)
{
	x86_unimplemented(regs, "xsha256");
}

X86_INSTRUCTION_DEF(xstore)
{
	x86_unimplemented(regs, "xstore");
}

X86_INSTRUCTION_DEF(xtest)
{
	x86_unimplemented(regs, "xtest");
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
