//
//  main.c
//  x86_emu_tests
//
//  Created by Félix on 2015-04-25.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <algorithm>
#include <cassert>
#include <stdio.h>
#include "x86_emulator.h"

using namespace std;

#define DECLARE_TEST(name) extern "C" void x86_test_ ## name (uintptr_t*, uintptr_t*, uintptr_t, uintptr_t);
#include "x86_tests.h"

namespace
{
	enum x86_flag
	{
		CF = 1 << 0,
		PF = 1 << 2,
		AF = 1 << 3,
		ZF = 1 << 6,
		SF = 1 << 7,
		OF = 1 << 11,
	};
	
	typedef void (*test_function)(uintptr_t* result, uintptr_t* flags, uintptr_t arg1, uintptr_t arg2);

	const x86_config config = { 64, X86_REG_RIP, X86_REG_RSP, X86_REG_RBP };
	static uint8_t emulator_stack[0x1000];

	template<typename T>
	uintptr_t as_uintptr(T* value)
	{
		return reinterpret_cast<uintptr_t>(value);
	}
	
	template<typename T>
	uintptr_t as_uintptr(T value)
	{
		return static_cast<uintptr_t>(value);
	}
}

struct x86_test_call
{
	struct result
	{
		uintptr_t value;
		uintptr_t flags;
	};
	
	test_function call;
	uint16_t relevant_flags;
	uintptr_t arg1;
	uintptr_t arg2;
	
	template<typename T, typename U>
	x86_test_call(test_function fn, uint16_t relevant_flags, T arg1, U arg2)
	: call(fn), relevant_flags(relevant_flags), arg1(as_uintptr(arg1)), arg2(as_uintptr(arg2))
	{
	}
	
	template<typename T>
	x86_test_call(test_function fn, uint16_t relevant_flags, T arg)
	: x86_test_call(fn, relevant_flags, arg, 0)
	{
	}
	
	explicit x86_test_call(test_function fn, uint16_t relevant_flags)
	: x86_test_call(call, relevant_flags, 0, 0)
	{
	}
	
	void test() const
	{
		result emulated, native;
		x86_regs regs = {
			.bp = { as_uintptr(__builtin_frame_address(0)) },
			.sp = { as_uintptr(end(emulator_stack)) },
			.di = { as_uintptr(&emulated.value) },
			.si = { as_uintptr(&emulated.flags) },
			.d = { arg1 },
			.c = { arg2 },
		};
		
		x86_call_intrin(&config, &regs, as_uintptr(call));
		call(&native.value, &native.flags, arg1, arg2);
		
		native.flags &= relevant_flags;
		emulated.flags &= relevant_flags;
		assert(native.value == emulated.value && native.flags == emulated.flags);
	}
};

const x86_test_call tests[] = {
	x86_test_call(&x86_test_mov, 0, 0xdeadbeef),
};


int main(int argc, const char * argv[]) {
	for (const x86_test_call& test : tests)
	{
		test.test();
	}
}
