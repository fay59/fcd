//
//  main.c
//  x86_emu_tests
//
//  Created by Félix on 2015-04-25.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <dlfcn.h>
#include <string>
#include "x86_emulator.h"

using namespace std;

#define DECLARE_TEST(name) extern "C" void x86_test_ ## name (uintptr_t*, uint16_t*, uintptr_t, uintptr_t);
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
	
	string flag_string(uint16_t v)
	{
		char flagChars[16];
		const char flagNames[16] = "C1P0A0ZSTIDO^N0";
		memset(flagChars, '.', sizeof flagChars);
		for (size_t i = 0; i < sizeof flagChars; i++)
		{
			if ((v >> i) & 1)
			{
				flagChars[i] = flagNames[i];
			}
		}
		return string(begin(flagChars), end(flagChars));
	}
	
	typedef void (*test_function)(uintptr_t* result, uint16_t* flags, uintptr_t arg1, uintptr_t arg2);
	extern "C" void x86_native_trampoline(uintptr_t*, uint16_t*, uintptr_t, uintptr_t, test_function, void*);
	const x86_config config = { 64, X86_REG_RIP, X86_REG_RSP, X86_REG_RBP };

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

struct x86_test_entry
{
	struct result
	{
		uint8_t stack[64];
		uintptr_t value;
		uint16_t flags;
		
		result()
		{
			value = 0;
			flags = 0;
			memset(stack, 0, sizeof stack);
		}
		
		string dump_stack()
		{
			const char hexgits[] = "0123456789abcdef";
			string result(80, '0');
			for (size_t i = 0; i < sizeof stack; i++)
			{
				result[i * 2] = hexgits[stack[i] >> 4];
				result[i * 2 + 1] = hexgits[stack[i] & 0xf];
			}
			return result;
		}
	};
	
	test_function call;
	uint16_t relevant_flags;
	uintptr_t arg1;
	uintptr_t arg2;
	
	template<typename T, typename U>
	x86_test_entry(test_function fn, uint16_t relevant_flags, T arg1, U arg2)
	: call(fn), relevant_flags(relevant_flags), arg1(as_uintptr(arg1)), arg2(as_uintptr(arg2))
	{
	}
	
	template<typename T>
	x86_test_entry(test_function fn, uint16_t relevant_flags, T arg)
	: x86_test_entry(fn, relevant_flags, arg, 0)
	{
	}
	
	explicit x86_test_entry(test_function fn, uint16_t relevant_flags)
	: x86_test_entry(fn, relevant_flags, 0, 0)
	{
	}
	
	void test() const
	{
		Dl_info info;
		if (dladdr(reinterpret_cast<void*>(call), &info) == 1)
		{
			printf("%s(", info.dli_sname);
			if (arg1 != 0 || arg2 != 0)
			{
				printf("%#lx", arg1);
				if (arg2 != 0)
				{
					printf(", %#lx", arg2);
				}
			}
			printf(")\n");
		}
		
		result emulated, native;
		x86_regs regs = {
			.bp = { as_uintptr(__builtin_frame_address(0)) },
			.sp = { as_uintptr(end(emulated.stack)) },
			.di = { as_uintptr(&emulated.value) },
			.si = { as_uintptr(&emulated.flags) },
			.d = { arg1 },
			.c = { arg2 },
		};
		
		x86_native_trampoline(&native.value, &native.flags, arg1, arg2, call, end(native.stack));
		x86_call_intrin(&config, &regs, as_uintptr(call));
		
		if (native.value != emulated.value)
		{
			printf("Result values are different\n");
			printf("Native:   %#lx\n", native.value);
			printf("Emulated: %#lx\n", emulated.value);
			abort();
		}
		
		uint64_t native_flags = native.flags & relevant_flags;
		uint64_t emulated_flags = emulated.flags & relevant_flags;
		if (native_flags != emulated_flags)
		{
			printf("Result flags are different\n");
			printf("Native:   %s\n", flag_string(native_flags).c_str());
			printf("Emulated: %s\n", flag_string(emulated_flags).c_str());
			abort();
		}
		puts("");
	}
};

const x86_test_entry tests[] = {
	x86_test_entry(&x86_test_adc32, OF|SF|ZF|AF|CF|PF, 0, 1),
	x86_test_entry(&x86_test_adc32, OF|SF|ZF|AF|CF|PF, 0x90000000, 0x90000000),
	x86_test_entry(&x86_test_adc32, OF|SF|ZF|AF|CF|PF, 0x7fffff00, 0x1ff),
	x86_test_entry(&x86_test_adc64, OF|SF|ZF|AF|CF|PF, 0, 1),
	x86_test_entry(&x86_test_adc64, OF|SF|ZF|AF|CF|PF, 0x9000000000000000, 0x9000000000000000),
	x86_test_entry(&x86_test_adc64, OF|SF|ZF|AF|CF|PF, 0x7fffffffffffff00, 0x1ff),
	
	x86_test_entry(&x86_test_and32, OF|SF|ZF|CF|PF, 0xaa000000, 0x80000000),
	x86_test_entry(&x86_test_and64, OF|SF|ZF|CF|PF, 100, 99),
	x86_test_entry(&x86_test_and64, OF|SF|ZF|CF|PF, 0xaa00000000000000, 0x8000000000000000),
	
	x86_test_entry(&x86_test_call, 0),
	
	x86_test_entry(&x86_test_cmov, 0, 0xdeadbeef, 0xfacefeed),
	
	x86_test_entry(&x86_test_cmp, OF|SF|ZF|AF|CF|PF, 0, 0),
	x86_test_entry(&x86_test_cmp, OF|SF|ZF|AF|CF|PF, 0, 1),
	x86_test_entry(&x86_test_cmp, OF|SF|ZF|AF|CF|PF, 1, 0),
	x86_test_entry(&x86_test_cmp, OF|SF|ZF|AF|CF|PF, 0x8000000000000000, 1),
	x86_test_entry(&x86_test_cmp, OF|SF|ZF|AF|CF|PF, 1, 0x8000000000000000),
	
	// imul doesn't set SF in earlier x86 CPUs, so don't test for it
	x86_test_entry(&x86_test_imul32, CF|OF, 0, 133),
	x86_test_entry(&x86_test_imul32, CF|OF, 1, 133),
	x86_test_entry(&x86_test_imul32, CF|OF, 2, 133),
	x86_test_entry(&x86_test_imul32, CF|OF, 0x10000000, 0x10),
	x86_test_entry(&x86_test_imul32, CF|OF, 0x40404040, 0x90909090),
	
	x86_test_entry(&x86_test_imul64, CF|OF, 0x1000000000000000, 0x10),
	x86_test_entry(&x86_test_imul64, CF|OF, 0x4040404040404043, 0x9090909090909095),
	
	x86_test_entry(&x86_test_j, 0),
	x86_test_entry(&x86_test_jcxz, 0),
	
	x86_test_entry(&x86_test_lea, 0, 0x1000, 0x2000),
	x86_test_entry(&x86_test_lea, 0, 0xF000000000000000, 0x2000000000000000),
	
	x86_test_entry(&x86_test_leave, 0),
	
	x86_test_entry(&x86_test_mov8, 0, 0xee),
	x86_test_entry(&x86_test_mov16, 0, 0xddee),
	x86_test_entry(&x86_test_mov32, 0, 0xbbccddee),
	x86_test_entry(&x86_test_mov64, 0, 0x778899aabbccddee),
};


int main(int argc, const char * argv[]) {
	for (const auto& test : tests)
	{
		test.test();
	}
}
