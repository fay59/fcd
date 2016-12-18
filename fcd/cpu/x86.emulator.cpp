//
// x86.emulator.cpp
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
#include "x86.emulator.h"
#include <cstring>
#include <limits.h>
#include <type_traits>

struct x86_effective_address
{
	x86_reg segment;
	uint64_t pointer;
};

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

template<typename TResultType>
[[gnu::always_inline]]
TResultType x86_read_dxax(CPTR(x86_regs) regs)
{
	constexpr size_t intSize = sizeof(TResultType);
	static_assert(intSize > 1, "Integer type too small");
	static_assert(intSize <= 16, "Integer type too large");
	static constexpr x86_reg regBySize[] = {
		[4] = X86_REG_AX,	[5] = X86_REG_DX,
		[8] = X86_REG_EAX,	[9] = X86_REG_EDX,
		[16] = X86_REG_RAX,	[17] = X86_REG_RDX,
	};
	
	TResultType result = static_cast<TResultType>(x86_read_reg(regs, regBySize[intSize + 1]));
	result <<= intSize * 8 / 2;
	result |= x86_read_reg(regs, regBySize[intSize]);
	return result;
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
static x86_effective_address x86_get_effective_address(CPTR(x86_regs) regs, CPTR(cs_x86_op) op)
{
	x86_effective_address result;
	const x86_op_mem* address = &op->mem;
	result.pointer = address->disp;
	if (address->segment == X86_REG_INVALID)
	{
		switch (address->base)
		{
			case X86_REG_BP:
			case X86_REG_EBP:
			case X86_REG_RBP:
				result.segment = X86_REG_SS;
				break;
				
			case X86_REG_IP:
			case X86_REG_EIP:
			case X86_REG_RIP:
				result.segment = X86_REG_CS;
				break;
				
			default:
				result.segment = X86_REG_INVALID;
		}
	}
	else
	{
		result.segment = static_cast<x86_reg>(address->segment);
	}
	
	if (address->index != X86_REG_INVALID)
	{
		uint64_t index = x86_read_reg(regs, static_cast<x86_reg>(address->index));
		result.pointer += index * address->scale;
	}
	
	if (address->base != X86_REG_INVALID)
	{
		result.pointer += x86_read_reg(regs, static_cast<x86_reg>(address->base));
	}
	return result;
}

[[gnu::always_inline]]
static uint64_t x86_read_mem(CPTR(x86_regs) regs, CPTR(cs_x86_op) op)
{
	auto address = x86_get_effective_address(regs, op);
	return x86_read_mem(address.segment, address.pointer, op->size);
}

[[gnu::always_inline]]
static void x86_write_mem(CPTR(x86_regs) regs, CPTR(cs_x86_op) op, uint64_t value)
{
	auto address = x86_get_effective_address(regs, op);
	x86_write_mem(address.segment, address.pointer, op->size, value);
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

template<typename T>
[[gnu::always_inline]]
static typename std::make_unsigned<T>::type x86_add_flags(PTR(x86_flags_reg) flags, uint64_t left, uint64_t right)
{
	typedef typename std::make_signed<T>::type sint;
	typedef typename std::make_unsigned<T>::type uint;
	
	uint unsignedResult;
	sint signedResult;
	flags->cf |= __builtin_add_overflow(static_cast<uint>(left), static_cast<uint>(right), &unsignedResult);
	flags->of |= __builtin_add_overflow(static_cast<sint>(left), static_cast<sint>(right), &signedResult);
	flags->sf = signedResult < 0;
	return unsignedResult;
}

[[gnu::always_inline]]
static uint64_t x86_add(PTR(x86_flags_reg) flags, size_t size, uint64_t left, uint64_t right)
{
	uint64_t result;
	switch (size)
	{
		case 1: result = x86_add_flags<int8_t>(flags, left, right); break;
		case 2: result = x86_add_flags<int16_t>(flags, left, right); break;
		case 4: result = x86_add_flags<int32_t>(flags, left, right); break;
		case 8: result = x86_add_flags<int64_t>(flags, left, right); break;
		default: x86_assertion_failure("invalid destination size");
	}
	
	flags->af |= (left & 0xf) + (right & 0xf) > 0xf;
	flags->zf = result == 0;
	flags->pf = x86_parity(result);
	return result;
}

template<typename T>
[[gnu::always_inline]]
static typename std::make_unsigned<T>::type x86_sub_flags(PTR(x86_flags_reg) flags, uint64_t left, uint64_t right)
{
	typedef typename std::make_signed<T>::type sint;
	typedef typename std::make_unsigned<T>::type uint;
	
	uint unsignedResult;
	sint signedResult;
	flags->cf |= __builtin_sub_overflow(static_cast<uint>(left), static_cast<uint>(right), &unsignedResult);
	flags->of |= __builtin_sub_overflow(static_cast<sint>(left), static_cast<sint>(right), &signedResult);
	flags->sf = signedResult < 0;
	return unsignedResult;
}

[[gnu::always_inline]]
static uint64_t x86_subtract(PTR(x86_flags_reg) flags, size_t size, uint64_t left, uint64_t right)
{
	uint64_t result;
	switch (size)
	{
		case 1: result = x86_sub_flags<int8_t>(flags, left, right); break;
		case 2: result = x86_sub_flags<int16_t>(flags, left, right); break;
		case 4: result = x86_sub_flags<int32_t>(flags, left, right); break;
		case 8: result = x86_sub_flags<int64_t>(flags, left, right); break;
		default: x86_assertion_failure("invalid destination size");
	}
	
	flags->af |= (left & 0xf) - (right & 0xf) > 0xf;
	flags->zf = result == 0;
	flags->pf = x86_parity(result);
	return result;
}

template<typename TOperator>
[[gnu::always_inline]]
static uint64_t x86_logical_operator(PTR(x86_regs) regs, PTR(x86_flags_reg) flags, CPTR(cs_x86) inst, TOperator&& func)
{
	const cs_x86_op* source = &inst->operands[1];
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t right = x86_read_source_operand(source, regs);
	
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
	x86_write_mem(X86_REG_SS, push_address, size, value);
	x86_write_reg(regs, config->sp, push_address);
}

[[gnu::always_inline]]
static uint64_t x86_pop_value(CPTR(x86_config) config, PTR(x86_regs) regs, size_t size)
{
	uint64_t pop_address = x86_read_reg(regs, config->sp);
	uint64_t popped = x86_read_mem(X86_REG_SS, pop_address, size);
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

[[gnu::always_inline]]
static void x86_move_sign_extend(PTR(x86_regs) regs, CPTR(cs_x86) inst)
{
	const cs_x86_op* source = &inst->operands[1];
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t value = x86_read_source_operand(source, regs);
	switch (source->size)
	{
		case 1: value = make_signed<int8_t>(value); break;
		case 2: value = make_signed<int16_t>(value); break;
		case 4: value = make_signed<int32_t>(value); break;
		case 8: value = make_signed<int64_t>(value); break;
		default: x86_assertion_failure("unknown operand size");
	}
	x86_write_destination_operand(destination, regs, value);
}

#pragma mark - Conditionals

[[gnu::always_inline]]
static bool x86_cond_above(CPTR(x86_flags_reg) flags)
{
	return !flags->cf & !flags->zf;
}

[[gnu::always_inline]]
static bool x86_cond_above_or_equal(CPTR(x86_flags_reg) flags)
{
	return !flags->cf;
}

[[gnu::always_inline]]
static bool x86_cond_below(CPTR(x86_flags_reg) flags)
{
	return flags->cf;
}

[[gnu::always_inline]]
static bool x86_cond_below_or_equal(CPTR(x86_flags_reg) flags)
{
	return flags->cf | flags->zf;
}

[[gnu::always_inline]]
static bool x86_cond_equal(CPTR(x86_flags_reg) flags)
{
	return flags->zf;
}

[[gnu::always_inline]]
static bool x86_cond_greater(CPTR(x86_flags_reg) flags)
{
	return !flags->zf & (flags->sf == flags->of);
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
	return flags->zf | (flags->sf != flags->of);
}

[[gnu::always_inline]]
static bool x86_cond_not_equal(CPTR(x86_flags_reg) flags)
{
	return !flags->zf;
}

[[gnu::always_inline]]
static bool x86_cond_no_overflow(CPTR(x86_flags_reg) flags)
{
	return !flags->of;
}

[[gnu::always_inline]]
static bool x86_cond_no_parity(CPTR(x86_flags_reg) flags)
{
	return !flags->pf;
}

[[gnu::always_inline]]
static bool x86_cond_no_sign(CPTR(x86_flags_reg) flags)
{
	return !flags->sf;
}

[[gnu::always_inline]]
static bool x86_cond_overflow(CPTR(x86_flags_reg) flags)
{
	return flags->of;
}

[[gnu::always_inline]]
static bool x86_cond_parity(CPTR(x86_flags_reg) flags)
{
	return flags->pf;
}

[[gnu::always_inline]]
static bool x86_cond_signed(CPTR(x86_flags_reg) flags)
{
	return flags->sf;
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

[[gnu::always_inline]]
static bool x86_rep_condition(CPTR(x86_config) config, PTR(x86_regs) regs, CPTR(cs_x86) inst)
{
	if (inst->prefix[0] == X86_PREFIX_REP)
	{
		x86_reg counter = config->address_size == 8 ? X86_REG_RCX : X86_REG_ECX;
		uint64_t registerValue = x86_read_reg(regs, counter);
		if (registerValue != 0)
		{
			x86_write_reg(regs, counter, registerValue - 1);
			return true;
		}
	}
	return false;
}

template<typename Int>
[[gnu::always_inline]]
static void x86_stos(CPTR(x86_config) config, PTR(x86_regs) regs, CPTR(x86_flags_reg) flags, CPTR(cs_x86) inst, const Int& writeValue)
{
	bool alwaysDoFirst = inst->prefix[0] != X86_PREFIX_REP;
	while (alwaysDoFirst || x86_rep_condition(config, regs, inst))
	{
		x86_reg addressRegister = config->address_size == 8 ? X86_REG_RDI : X86_REG_EDI;
		uint64_t address = x86_read_reg(regs, addressRegister);
		x86_write_mem(X86_REG_ES, x86_read_reg(regs, addressRegister), sizeof writeValue, writeValue);
		x86_write_reg(regs, addressRegister, address + (flags->df ? -1 : 1) * sizeof writeValue);
		alwaysDoFirst = false;
	}
}

#pragma mark - Helpers
extern "C" void x86_function_prologue(CPTR(x86_config) config, PTR(x86_regs) regs, PTR(x86_flags_reg) flags)
{
	uint64_t ip = x86_read_reg(regs, config->ip);
	x86_push_value(config, regs, config->address_size, ip);
	
	// Uh-oh: this might not always be true. There's not much to do about it, though.
	flags->df = false;
}

#pragma mark - Instruction Implementation
X86_INSTRUCTION_DEF(adc)
{
	const cs_x86_op* source = &inst->operands[1];
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t right = x86_read_source_operand(source, regs);
	uint64_t result = flags->cf;
	
	memset(flags, 0, sizeof *flags);
	result = x86_add(flags, source->size, result, left);
	result = x86_add(flags, source->size, result, right);
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(add)
{
	const cs_x86_op* source = &inst->operands[1];
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t right = x86_read_source_operand(source, regs);
	
	memset(flags, 0, sizeof *flags);
	uint64_t result = x86_add(flags, source->size, left, right);
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(and)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t result = x86_logical_operator(regs, flags, inst, [](uint64_t left, uint64_t right) { return left & right; });
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(bt)
{
	uint64_t bitBase = x86_read_source_operand(&inst->operands[0], regs);
	uint64_t bitOffset = x86_read_source_operand(&inst->operands[1], regs);
	flags->cf = (bitBase >> bitOffset) & 1;
	flags->af = x86_clobber_bit();
	flags->of = x86_clobber_bit();
	flags->pf = x86_clobber_bit();
	flags->zf = x86_clobber_bit();
}

X86_INSTRUCTION_DEF(call)
{
	uint64_t target = x86_read_source_operand(&inst->operands[0], regs);
	x86_call_intrin(config, regs, target);
}

X86_INSTRUCTION_DEF(cdq)
{
	int32_t signedAx = static_cast<int32_t>(x86_read_reg(regs, X86_REG_EAX));
	x86_write_reg(regs, X86_REG_EDX, signedAx < 0 ? 0xffffffff : 0);
}

X86_INSTRUCTION_DEF(cdqe)
{
	int32_t signedAx = static_cast<int32_t>(x86_read_reg(regs, X86_REG_EAX));
	int64_t signExtendedAx = static_cast<int64_t>(signedAx);
	x86_write_reg(regs, X86_REG_RAX, signExtendedAx);
}

X86_INSTRUCTION_DEF(cmova)
{
	if (x86_cond_above(flags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovae)
{
	if (x86_cond_above_or_equal(flags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovb)
{
	if (x86_cond_below(flags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovbe)
{
	if (x86_cond_below_or_equal(flags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmove)
{
	if (x86_cond_equal(flags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovg)
{
	if (x86_cond_greater(flags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovge)
{
	if (x86_cond_greater_or_equal(flags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovl)
{
	if (x86_cond_less(flags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovle)
{
	if (x86_cond_less_or_equal(flags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovne)
{
	if (x86_cond_not_equal(flags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovno)
{
	if (x86_cond_no_overflow(flags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovnp)
{
	if (x86_cond_no_parity(flags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovns)
{
	if (x86_cond_no_sign(flags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovo)
{
	if (x86_cond_overflow(flags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovp)
{
	if (x86_cond_parity(flags))
	{
		x86_move_zero_extend(regs, inst);
	}
}

X86_INSTRUCTION_DEF(cmovs)
{
	if (x86_cond_signed(flags))
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
	
	memset(flags, 0, sizeof *flags);
	x86_subtract(flags, left->size, leftValue, rightValue);
}

X86_INSTRUCTION_DEF(cqo)
{
	int64_t signedAx = static_cast<int64_t>(x86_read_reg(regs, X86_REG_RAX));
	x86_write_reg(regs, X86_REG_RDX, signedAx < 0 ? 0xffffffffffffffffull : 0);
}

X86_INSTRUCTION_DEF(dec)
{
	bool preserved_cf = flags->cf;
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	
	memset(flags, 0, sizeof *flags);
	uint64_t result = x86_subtract(flags, destination->size, left, 1);
	x86_write_destination_operand(destination, regs, result);
	flags->cf = preserved_cf;
}

X86_INSTRUCTION_DEF(div)
{
	// XXX: div can raise exceptions, but we don't support CPU exceptions.
	
	const cs_x86_op* divisor_op = &inst->operands[0];
	if (divisor_op->size == 1)
	{
		uint8_t divisor = static_cast<uint8_t>(x86_read_source_operand(divisor_op, regs));
		uint16_t dividend = static_cast<uint16_t>(x86_read_reg(regs, X86_REG_AX));
		x86_write_reg(regs, X86_REG_AL, dividend / divisor);
		x86_write_reg(regs, X86_REG_AH, dividend % divisor);
	}
	else if (divisor_op->size == 2)
	{
		uint16_t divisor = static_cast<uint16_t>(x86_read_source_operand(divisor_op, regs));
		uint32_t dividend = x86_read_dxax<uint32_t>(regs);
		x86_write_reg(regs, X86_REG_AX, dividend / divisor);
		x86_write_reg(regs, X86_REG_DX, dividend % divisor);
	}
	else if (divisor_op->size == 4)
	{
		uint32_t divisor = static_cast<uint32_t>(x86_read_source_operand(divisor_op, regs));
		uint64_t dividend = x86_read_dxax<uint64_t>(regs);
		x86_write_reg(regs, X86_REG_EAX, dividend / divisor);
		x86_write_reg(regs, X86_REG_EDX, dividend % divisor);
	}
	else if (divisor_op->size == 8)
	{
		uint64_t divisor = x86_read_source_operand(divisor_op, regs);
		__uint128_t dividend = x86_read_dxax<__uint128_t>(regs);
		x86_write_reg(regs, X86_REG_RAX, dividend / divisor);
		x86_write_reg(regs, X86_REG_RDX, dividend % divisor);
	}
	else
	{
		x86_assertion_failure("unexpected operand size");
	}
	
	// every flag is undefined.
	flags->af = x86_clobber_bit();
	flags->cf = x86_clobber_bit();
	flags->of = x86_clobber_bit();
	flags->pf = x86_clobber_bit();
	flags->sf = x86_clobber_bit();
	flags->zf = x86_clobber_bit();
}

X86_INSTRUCTION_DEF(hlt)
{
	__builtin_trap();
}

X86_INSTRUCTION_DEF(idiv)
{
	// XXX: idiv can raise exceptions, but we don't support CPU exceptions.
	
	const cs_x86_op* divisor_op = &inst->operands[0];
	if (divisor_op->size == 1)
	{
		int8_t divisor = static_cast<int8_t>(x86_read_source_operand(divisor_op, regs));
		int16_t dividend = static_cast<int16_t>(x86_read_reg(regs, X86_REG_AX));
		x86_write_reg(regs, X86_REG_AL, dividend / divisor);
		x86_write_reg(regs, X86_REG_AH, dividend % divisor);
	}
	else if (divisor_op->size == 2)
	{
		int16_t divisor = static_cast<int16_t>(x86_read_source_operand(divisor_op, regs));
		int32_t dividend = x86_read_dxax<int32_t>(regs);
		x86_write_reg(regs, X86_REG_AX, dividend / divisor);
		x86_write_reg(regs, X86_REG_DX, dividend % divisor);
	}
	else if (divisor_op->size == 4)
	{
		int32_t divisor = static_cast<int32_t>(x86_read_source_operand(divisor_op, regs));
		int64_t dividend = x86_read_dxax<int64_t>(regs);
		x86_write_reg(regs, X86_REG_EAX, dividend / divisor);
		x86_write_reg(regs, X86_REG_EDX, dividend % divisor);
	}
	else if (divisor_op->size == 8)
	{
		int64_t divisor = x86_read_source_operand(divisor_op, regs);
		__int128_t dividend = x86_read_dxax<__int128_t>(regs);
		x86_write_reg(regs, X86_REG_RAX, dividend / divisor);
		x86_write_reg(regs, X86_REG_RDX, dividend % divisor);
	}
	else
	{
		x86_assertion_failure("unexpected operand size");
	}
	
	// every flag is undefined.
	flags->af = x86_clobber_bit();
	flags->cf = x86_clobber_bit();
	flags->of = x86_clobber_bit();
	flags->pf = x86_clobber_bit();
	flags->sf = x86_clobber_bit();
	flags->zf = x86_clobber_bit();
}

X86_INSTRUCTION_DEF(imul)
{
	// SF had undefined contents up until relatively recently. Set it, but don't check it with tests
	// (the implementation is trivial anyway).
	
	// imul has 3 variations:
	// - imul r/m
	// - imul r, r/m
	// - imul r, r/m, imm
	// Special handling for first form, which requires 128-bit integral types.
	
	const cs_x86_op* op0 = &inst->operands[0];
	if (inst->op_count == 1)
	{
		int64_t multiplyBy = x86_read_source_operand(op0, regs);
		if (op0->size == 1)
		{
			int64_t result = x86_read_reg(regs, X86_REG_AL) * multiplyBy;
			x86_write_reg(regs, X86_REG_AX, result);
			int8_t al = result & 0xff;
			
			flags->cf = al != result;
			flags->of = al != result;
			flags->sf = al < 0;
		}
		else if (op0->size == 2)
		{
			int64_t result = x86_read_reg(regs, X86_REG_AX) * multiplyBy;
			int16_t dx = static_cast<int16_t>(result >> 16);
			int16_t ax = static_cast<int16_t>(result);
			x86_write_reg(regs, X86_REG_DX, dx);
			x86_write_reg(regs, X86_REG_AX, ax);
			
			flags->cf = ax != result;
			flags->of = ax != result;
			flags->sf = ax < 0;
		}
		else if (op0->size == 4)
		{
			int64_t result = x86_read_reg(regs, X86_REG_EAX) * multiplyBy;
			int32_t edx = static_cast<int32_t>(result >> 32);
			int32_t eax = static_cast<int32_t>(result);
			x86_write_reg(regs, X86_REG_EDX, edx);
			x86_write_reg(regs, X86_REG_EAX, eax);
			
			flags->cf = eax != result;
			flags->of = eax != result;
			flags->sf = eax < 0;
		}
		else if (op0->size == 8)
		{
			__int128_t result = x86_read_reg(regs, X86_REG_RAX);
			result *= multiplyBy;
			int64_t rdx = static_cast<int64_t>(result >> 64);
			int64_t rax = static_cast<int64_t>(result);
			x86_write_reg(regs, X86_REG_RDX, rdx);
			x86_write_reg(regs, X86_REG_RAX, rax);
			
			flags->cf = rax != result;
			flags->of = rax != result;
			flags->sf = rax < 0;
		}
		else
		{
			x86_assertion_failure("unexpected multiply size");
		}
	}
	else
	{
		int64_t left, right;
		if (inst->op_count == 2)
		{
			left = x86_read_destination_operand(op0, regs);
			right = x86_read_source_operand(&inst->operands[1], regs);
		}
		else if (inst->op_count == 3)
		{
			left = x86_read_source_operand(&inst->operands[1], regs);
			right = x86_read_source_operand(&inst->operands[2], regs);
		}
		else
		{
			x86_assertion_failure("unexpected number of operands");
		}
		
		int64_t result;
		switch (op0->size)
		{
			case 1:
			{
				using result_type = int8_t;
				left = make_signed<result_type>(left);
				right = make_signed<result_type>(right);
				result = left * right;
				auto truncated = static_cast<result_type>(result);
				flags->cf = flags->of = truncated != result;
				flags->sf = truncated < 0;
				break;
			}
				
			case 2:
			{
				using result_type = int16_t;
				left = make_signed<result_type>(left);
				right = make_signed<result_type>(right);
				result = left * right;
				auto truncated = static_cast<result_type>(result);
				flags->cf = flags->of = truncated != result;
				flags->sf = truncated < 0;
				break;
			}
				
			case 4:
			{
				using result_type = int32_t;
				left = make_signed<result_type>(left);
				right = make_signed<result_type>(right);
				result = left * right;
				auto truncated = static_cast<result_type>(result);
				flags->cf = flags->of = truncated != result;
				flags->sf = truncated < 0;
				break;
			}
				
			case 8:
			{
				long long mul_result;
				flags->cf = flags->of = __builtin_smulll_overflow(left, right, &mul_result);
				flags->sf = result < 0;
				result = mul_result;
				break;
			}
				
			default: x86_assertion_failure("unexpected multiply size");
		}
		
		x86_write_destination_operand(op0, regs, result); // will be truncated down the pipeline
	}
	flags->af = x86_clobber_bit();
	flags->pf = x86_clobber_bit();
	flags->zf = x86_clobber_bit();
}

X86_INSTRUCTION_DEF(inc)
{
	bool preserved_cf = flags->cf;
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	
	memset(flags, 0, sizeof *flags);
	uint64_t result = x86_add(flags, destination->size, left, 1);
	x86_write_destination_operand(destination, regs, result);
	flags->cf = preserved_cf;
}

X86_INSTRUCTION_DEF(ja)
{
	x86_conditional_jump(config, regs, inst, x86_cond_above(flags));
}

X86_INSTRUCTION_DEF(jae)
{
	x86_conditional_jump(config, regs, inst, x86_cond_above_or_equal(flags));
}

X86_INSTRUCTION_DEF(jb)
{
	x86_conditional_jump(config, regs, inst, x86_cond_below(flags));
}

X86_INSTRUCTION_DEF(jbe)
{
	x86_conditional_jump(config, regs, inst, x86_cond_below_or_equal(flags));
}

X86_INSTRUCTION_DEF(jcxz)
{
	x86_conditional_jump(config, regs, inst, x86_read_reg(regs, X86_REG_CX) == 0);
}

X86_INSTRUCTION_DEF(je)
{
	x86_conditional_jump(config, regs, inst, x86_cond_equal(flags));
}

X86_INSTRUCTION_DEF(jecxz)
{
	x86_conditional_jump(config, regs, inst, x86_read_reg(regs, X86_REG_ECX) == 0);
}

X86_INSTRUCTION_DEF(jg)
{
	x86_conditional_jump(config, regs, inst, x86_cond_greater(flags));
}

X86_INSTRUCTION_DEF(jge)
{
	x86_conditional_jump(config, regs, inst, x86_cond_greater_or_equal(flags));
}

X86_INSTRUCTION_DEF(jl)
{
	x86_conditional_jump(config, regs, inst, x86_cond_less(flags));
}

X86_INSTRUCTION_DEF(jle)
{
	x86_conditional_jump(config, regs, inst, x86_cond_less_or_equal(flags));
}

X86_INSTRUCTION_DEF(jmp)
{
	uint64_t location = x86_read_source_operand(&inst->operands[0], regs);
	x86_jump_intrin(config, regs, location);
}

X86_INSTRUCTION_DEF(jne)
{
	x86_conditional_jump(config, regs, inst, x86_cond_not_equal(flags));
}

X86_INSTRUCTION_DEF(jno)
{
	x86_conditional_jump(config, regs, inst, x86_cond_no_overflow(flags));
}

X86_INSTRUCTION_DEF(jnp)
{
	x86_conditional_jump(config, regs, inst, x86_cond_no_parity(flags));
}

X86_INSTRUCTION_DEF(jns)
{
	x86_conditional_jump(config, regs, inst, x86_cond_no_sign(flags));
}

X86_INSTRUCTION_DEF(jo)
{
	x86_conditional_jump(config, regs, inst, x86_cond_overflow(flags));
}

X86_INSTRUCTION_DEF(jp)
{
	x86_conditional_jump(config, regs, inst, x86_cond_parity(flags));
}

X86_INSTRUCTION_DEF(jrcxz)
{
	x86_conditional_jump(config, regs, inst, x86_read_reg(regs, X86_REG_RCX) == 0);
}

X86_INSTRUCTION_DEF(js)
{
	x86_conditional_jump(config, regs, inst, x86_cond_signed(flags));
}

X86_INSTRUCTION_DEF(lea)
{
	const cs_x86_op* destination = &inst->operands[0];
	const cs_x86_op* source = &inst->operands[1];
	auto address = x86_get_effective_address(regs, source);
	x86_write_destination_operand(destination, regs, address.pointer);
}

X86_INSTRUCTION_DEF(leave)
{
	regs->sp = regs->bp;
	regs->bp.qword = x86_pop_value(config, regs, config->address_size);
}

X86_INSTRUCTION_DEF(mov)
{
	x86_move_zero_extend(regs, inst);
}

X86_INSTRUCTION_DEF(movabs)
{
	x86_move_zero_extend(regs, inst);
}

X86_INSTRUCTION_DEF(movsx)
{
	x86_move_sign_extend(regs, inst);
}

X86_INSTRUCTION_DEF(movsxd)
{
	x86_move_sign_extend(regs, inst);
}

X86_INSTRUCTION_DEF(movzx)
{
	x86_move_zero_extend(regs, inst);
}

X86_INSTRUCTION_DEF(mul)
{
	const cs_x86_op* op0 = &inst->operands[0];
	uint64_t a, d;
	uint64_t multiplyBy = x86_read_source_operand(op0, regs);
	if (op0->size == 1)
	{
		uint64_t result = x86_read_reg(regs, X86_REG_AL) * multiplyBy;
		a = result & 0xff;
		d = result >> 8;
		x86_write_reg(regs, X86_REG_AX, result);
	}
	else if (op0->size == 2)
	{
		uint64_t result = x86_read_reg(regs, X86_REG_AX) * multiplyBy;
		d = static_cast<uint16_t>(result >> 16);
		a = static_cast<uint16_t>(result);
		x86_write_reg(regs, X86_REG_DX, d);
		x86_write_reg(regs, X86_REG_AX, a);
	}
	else if (op0->size == 4)
	{
		uint64_t result = x86_read_reg(regs, X86_REG_EAX) * multiplyBy;
		d = static_cast<uint32_t>(result >> 32);
		a = static_cast<uint32_t>(result);
		x86_write_reg(regs, X86_REG_EDX, d);
		x86_write_reg(regs, X86_REG_EAX, a);
	}
	else if (op0->size == 8)
	{
		__uint128_t result = x86_read_reg(regs, X86_REG_RAX);
		result *= multiplyBy;
		d = static_cast<uint64_t>(result >> 64);
		a = static_cast<uint64_t>(result);
		x86_write_reg(regs, X86_REG_RDX, d);
		x86_write_reg(regs, X86_REG_RAX, a);
	}
	else
	{
		x86_assertion_failure("unexpected multiply size");
	}
	
	flags->af = x86_clobber_bit();
	flags->cf = d > 0;
	flags->of = d > 0;
	flags->pf = x86_clobber_bit();
	flags->sf = x86_clobber_bit();
	flags->zf = x86_clobber_bit();
}

X86_INSTRUCTION_DEF(neg)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t valueToNegate = x86_read_source_operand(destination, regs);
	
	memset(flags, 0, sizeof *flags);
	uint64_t result = x86_subtract(flags, destination->size, 0, valueToNegate);
	x86_write_destination_operand(destination, regs, result);
	flags->cf = valueToNegate != 0;
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
	uint64_t result = x86_logical_operator(regs, flags, inst, [](uint64_t left, uint64_t right) { return left | right; });
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(pop)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t popped = x86_pop_value(config, regs, destination->size);
	x86_write_destination_operand(destination, regs, popped);
}

X86_INSTRUCTION_DEF(popf)
{
	size_t size = inst->prefix[2] == 0x66
		? 2 // override 16 bits
		: config->address_size;
	
	uint64_t flatFlags = x86_pop_value(config, regs, size);
	flags->cf = flatFlags & 1;
	flatFlags >>= 2;
	flags->pf = flatFlags & 1;
	flatFlags >>= 2;
	flags->af = flatFlags & 1;
	flatFlags >>= 2;
	flags->zf = flatFlags & 1;
	flatFlags >>= 1;
	flags->sf = flatFlags & 1;
	flatFlags >>= 3;
	flags->df = flatFlags & 1;
	flatFlags >>= 1;
	flags->of = flatFlags & 1;
}

X86_INSTRUCTION_DEF(push)
{
	const cs_x86_op* source = &inst->operands[0];
	uint64_t pushed = x86_read_source_operand(source, regs);
	x86_push_value(config, regs, source->size, pushed);
}

X86_INSTRUCTION_DEF(pushf)
{
	uint64_t flatFlags = 0;
	flatFlags |= flags->of;
	flatFlags <<= 1;
	flatFlags |= flags->df;
	flatFlags <<= 1;
	flatFlags |= 1;
	flatFlags <<= 2;
	flatFlags |= flags->sf;
	flatFlags <<= 1;
	flatFlags |= flags->zf;
	flatFlags <<= 2;
	flatFlags |= flags->af;
	flatFlags <<= 2;
	flatFlags |= flags->pf;
	flatFlags <<= 1;
	flatFlags |= 1;
	flatFlags <<= 1;
	flatFlags |= flags->cf;
	
	size_t size = inst->prefix[2] == 0x66
		? 2 // override 16 bits
		: config->address_size;
	x86_push_value(config, regs, size, flatFlags);
}

X86_INSTRUCTION_DEF(ret)
{
	uint64_t return_adress = x86_pop_value(config, regs, config->address_size);
	x86_write_reg(regs, config->ip, return_adress);
	x86_ret_intrin(config, regs);
}

X86_INSTRUCTION_DEF(rol)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t shiftAmount = x86_read_source_operand(&inst->operands[1], regs);
	shiftAmount &= make_mask(destination->size == 8 ? 6 : 5);
	
	if (shiftAmount != 0)
	{
		size_t bitSize = destination->size * CHAR_BIT;
		uint64_t leftPart = left << shiftAmount;
		uint64_t rightPart = (left >> (bitSize - shiftAmount)) & make_mask(shiftAmount);
		uint64_t result = leftPart | rightPart;
		
		x86_write_destination_operand(destination, regs, result);
		flags->cf = result & 1;
		if (shiftAmount == 1)
		{
			flags->of = flags->cf ^ ((result >> (bitSize - 1)) & 1);
		}
		else
		{
			flags->of = x86_clobber_bit();
		}
	}
}

X86_INSTRUCTION_DEF(ror)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t shiftAmount = x86_read_source_operand(&inst->operands[1], regs);
	shiftAmount &= make_mask(destination->size == 8 ? 6 : 5);
	
	if (shiftAmount != 0)
	{
		size_t bitSize = destination->size * CHAR_BIT;
		uint64_t leftPart = left >> shiftAmount;
		uint64_t rightPart = (left & make_mask(shiftAmount)) << (bitSize - shiftAmount);
		uint64_t result = leftPart | rightPart;
	
		x86_write_destination_operand(destination, regs, result);
		flags->cf = (result >> (bitSize - 1)) & 1;
		if (shiftAmount == 1)
		{
			uint8_t topmostBits = result >> (bitSize - 2);
			flags->of = topmostBits == 1 || topmostBits == 2;
		}
		else
		{
			flags->of = x86_clobber_bit();
		}
	}
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
	if (shiftAmount != 0)
	{
		int64_t result = signedLeft >> shiftAmount;
		x86_write_destination_operand(destination, regs, result);
		
		flags->cf = (signedLeft >> (shiftAmount - 1)) & 1;
		flags->of = shiftAmount == 1 ? 0 : x86_clobber_bit();
		flags->sf = (result >> (destination->size * CHAR_BIT - 1)) & 1;
		flags->pf = x86_parity(result);
		flags->zf = result == 0;
		flags->af = x86_clobber_bit();
	}
}

X86_INSTRUCTION_DEF(sbb)
{
	const cs_x86_op* source = &inst->operands[1];
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t right = x86_read_source_operand(source, regs);
	uint64_t result = left;
	uint64_t carry = static_cast<uint64_t>(flags->cf);
	
	memset(flags, 0, sizeof *flags);
	result = x86_subtract(flags, source->size, result, right);
	result = x86_subtract(flags, source->size, result, carry);
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(seta)
{
	bool cond = x86_cond_above(flags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setae)
{
	bool cond = x86_cond_above_or_equal(flags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setb)
{
	bool cond = x86_cond_below(flags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setbe)
{
	bool cond = x86_cond_below_or_equal(flags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(sete)
{
	bool cond = x86_cond_equal(flags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setg)
{
	bool cond = x86_cond_greater(flags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setge)
{
	bool cond = x86_cond_greater_or_equal(flags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setl)
{
	bool cond = x86_cond_less(flags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setle)
{
	bool cond = x86_cond_less_or_equal(flags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setne)
{
	bool cond = x86_cond_not_equal(flags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setno)
{
	bool cond = x86_cond_no_overflow(flags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setnp)
{
	bool cond = x86_cond_no_parity(flags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setns)
{
	bool cond = x86_cond_no_sign(flags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(seto)
{
	bool cond = x86_cond_overflow(flags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(setp)
{
	bool cond = x86_cond_parity(flags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(sets)
{
	bool cond = x86_cond_signed(flags);
	x86_write_destination_operand(&inst->operands[0], regs, cond);
}

X86_INSTRUCTION_DEF(shl)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t shiftAmount = x86_read_source_operand(&inst->operands[1], regs);
	shiftAmount &= make_mask(destination->size == 8 ? 6 : 5);
	uint64_t result = left << shiftAmount;
	
	if (shiftAmount != 0)
	{
		x86_write_destination_operand(destination, regs, result);
		flags->cf = (left >> (CHAR_BIT * destination->size - shiftAmount)) & 1;
		if (shiftAmount == 1)
		{
			uint8_t topmostBits = left >> (CHAR_BIT * destination->size - 2) & 3;
			flags->of = topmostBits == 1 || topmostBits == 2;
		}
		else
		{
			flags->of = x86_clobber_bit();
		}
		flags->sf = (result >> (destination->size * CHAR_BIT - 1)) & 1;
		flags->pf = x86_parity(result);
		flags->zf = result == 0;
		flags->af = x86_clobber_bit();
	}
}

X86_INSTRUCTION_DEF(shr)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t shiftAmount = x86_read_source_operand(&inst->operands[1], regs);
	shiftAmount &= make_mask(destination->size == 8 ? 6 : 5);
	if (shiftAmount != 0)
	{
		uint64_t result = left >> shiftAmount;
		
		x86_write_destination_operand(destination, regs, result);
		flags->cf = (left >> (shiftAmount - 1)) & 1;
		flags->of = shiftAmount == 1 ? (left >> (destination->size * CHAR_BIT - 1)) & 1 : x86_clobber_bit();
		flags->sf = (result >> (destination->size * CHAR_BIT - 1)) & 1;
		flags->pf = x86_parity(result);
		flags->zf = result == 0;
		flags->af = x86_clobber_bit();
	}
}

X86_INSTRUCTION_DEF(stc)
{
	flags->cf = 1;
}

X86_INSTRUCTION_DEF(stosb)
{
	x86_stos(config, regs, flags, inst, regs->a.low.low.low);
}

X86_INSTRUCTION_DEF(stosd)
{
	x86_stos(config, regs, flags, inst, regs->a.low.low.word);
}

X86_INSTRUCTION_DEF(stosq)
{
	x86_stos(config, regs, flags, inst, regs->a.qword);
}

X86_INSTRUCTION_DEF(stosw)
{
	x86_stos(config, regs, flags, inst, regs->a.low.dword);
}

X86_INSTRUCTION_DEF(sub)
{
	const cs_x86_op* source = &inst->operands[1];
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t left = x86_read_destination_operand(destination, regs);
	uint64_t right = x86_read_source_operand(source, regs);
	
	memset(flags, 0, sizeof *flags);
	uint64_t result = x86_subtract(flags, destination->size, left, right);
	x86_write_destination_operand(destination, regs, result);
}

X86_INSTRUCTION_DEF(test)
{
	x86_logical_operator(regs, flags, inst, [](uint64_t left, uint64_t right) { return left & right; });
}

X86_INSTRUCTION_DEF(xor)
{
	const cs_x86_op* destination = &inst->operands[0];
	uint64_t result = x86_logical_operator(regs, flags, inst, [](uint64_t left, uint64_t right) { return left ^ right; });
	x86_write_destination_operand(destination, regs, result);
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
	//	[X86_REG_K0]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::k0}},
	//	[X86_REG_K1]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::k1}},
	//	[X86_REG_K2]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::k2}},
	//	[X86_REG_K3]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::k3}},
	//	[X86_REG_K4]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::k4}},
	//	[X86_REG_K5]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::k5}},
	//	[X86_REG_K6]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::k6}},
	//	[X86_REG_K7]	= {.type = x86_reg_type::qword_reg,	.size = 8,	.reg = {&x86_regs::k7}},
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
