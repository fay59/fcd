//
//  x86_intrin_impl.cpp
//  x86Emulator
//
//  Created by Félix on 2015-04-25.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <algorithm>
#include <cassert>
#include <csetjmp>
#include <iostream>

#include "capstone_wrapper.h"
#include "x86_emulator.h"

using namespace std;

namespace
{
	jmp_buf jump_to;

	typedef void (*x86_impl)(CPTR(x86_config), CPTR(cs_x86), PTR(x86_regs), PTR(x86_flags_reg));
	x86_impl emulator_funcs[] = {
#define X86_INSTRUCTION_DECL(enum, shortName) [enum] = &x86_##shortName,
#include "x86_defs.h"
	};
	
	template<typename TInt>
	void write_at(uintptr_t address, uint64_t value)
	{
		*reinterpret_cast<TInt*>(address) = static_cast<TInt>(value);
	}

	template<typename TInt>
	TInt read_at(uintptr_t address)
	{
		return *reinterpret_cast<TInt*>(address);
	}
}

extern const char x86_test_epilogue[];
	
extern "C" void x86_write_mem(uint64_t address, size_t size, uint64_t value)
{
	switch (size)
	{
		case 1: write_at<uint8_t>(address, value); break;
		case 2: write_at<uint16_t>(address, value); break;
		case 4: write_at<uint32_t>(address, value); break;
		case 8: write_at<uint64_t>(address, value); break;
		default: abort();
	}
}

extern "C" uint64_t x86_read_mem(uint64_t address, size_t size)
{
	switch (size)
	{
		case 1: return read_at<uint8_t>(address);
		case 2: return read_at<uint16_t>(address);
		case 4: return read_at<uint32_t>(address);
		case 8: return read_at<uint64_t>(address);
		default: abort();
	}
}

extern "C" void x86_call_intrin(CPTR(x86_config) config, PTR(x86_regs) regs, uint64_t target)
{
	cs_mode size;
	uint64_t return_to = regs->ip.qword;
	if (config->address_size == 4)
	{
		regs->sp.low.dword -= 4;
		write_at<uint32_t>(regs->sp.low.dword, regs->ip.low.dword);
		regs->ip.qword = static_cast<uint32_t>(target);
		size = CS_MODE_32;
	}
	else if (config->address_size == 8)
	{
		regs->sp.qword -= 8;
		write_at<uint64_t>(regs->sp.qword, regs->ip.qword);
		regs->ip.qword = target;
		size = CS_MODE_64;
	}
	else
	{
		abort();
	}
	
	// stuck with setjmp because the functions are marked noreturn
	jmp_buf previous;
	copy(begin(jump_to), end(jump_to), begin(previous));

	x86_flags_reg flags;
	unique_ptr<capstone> cs;
	if (auto csHandle = capstone::create(CS_ARCH_X86, CS_MODE_LITTLE_ENDIAN | size))
	{
		cs.reset(new capstone(move(csHandle.get())));
	}
	else
	{
		// This is REALLY not supposed to happen. The parameters are static.
		// XXX: If/when we have other architectures, change this to something non-fatal.
		cerr << "couldn't open Capstone handle: " << csHandle.getError().message() << endl;
		abort();
	}
	
	bool print = true;
	while (true)
	{
		auto code_begin = reinterpret_cast<const uint8_t*>(regs->ip.qword);
		auto code_end = reinterpret_cast<const uint8_t*>(UINTPTR_MAX);
		auto iter = cs->begin(code_begin, code_end, regs->ip.qword);
		
		int cause = setjmp(jump_to);
		if (cause == 0)
		{
			while (iter.next() == capstone_iter::success)
			{
				print &= iter->address != reinterpret_cast<uintptr_t>(&x86_test_epilogue);
				if (print)
				{
					printf("%llx %6s %s\n", iter->address, iter->mnemonic, iter->op_str);
				}
				
				regs->ip.qword = iter.next_address();
				emulator_funcs[iter->id](config, &iter->detail->x86, regs, &flags);
			}
			assert(!"unreachable");
		}
		else if (cause == 1)
		{
			// return
			assert(regs->ip.qword == return_to);
			break;
		}
		else if (cause == 2)
		{
			// back from a jump, just keep going
		}
		else
		{
			abort();
		}
	}
	
	copy(begin(previous), end(previous), begin(jump_to));
}

NORETURN extern "C" void x86_ret_intrin(CPTR(x86_config), PTR(x86_regs))
{
	longjmp(jump_to, 1);
}

NORETURN extern "C" void x86_jump_intrin(CPTR(x86_config), PTR(x86_regs) regs, uint64_t destination)
{
	regs->ip.qword = destination;
	longjmp(jump_to, 2);
}

NORETURN extern "C" void x86_assertion_failure(CPTR(char) problem)
{
	cerr << problem << endl;
	abort();
}

NORETURN extern "C" void x86_unimplemented(PTR(x86_regs), CPTR(char) inst)
{
	x86_assertion_failure("Instruction not implemented");
}
