//
//  brainfuck.cpp
//  interpiler
//
//  Created by Félix on 2015-04-12.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

// For testing purposes
// (sorry for the bad word mom)
// ~/Projets/OpenSource/lldb/llvm/Release+Asserts/bin/clang++ -S -emit-llvm -O3 --std=c++14 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.10.sdk -o ~/Desktop/x86Emulator/interpiler/bf.S ~/Desktop/x86Emulator/interpiler/bf.cpp

struct bf_state
{
	unsigned char memory[0x1000];
	unsigned long index;
	unsigned long ip;
};

bf_state staticState = {0};

// intrinsics
extern "C" void bf_skip_scope(bf_state* state);
extern "C" void bf_rewind_scope(bf_state* state);

// external symbols
[[gnu::noreturn]]
extern "C" void abort();

extern "C" long read(int, void*, unsigned long);
extern "C" long write(int, void*, unsigned long);
extern "C" int puts(const char*);

// helpers
template<typename T, unsigned long N>
[[gnu::always_inline]]
constexpr unsigned long countof(T (&)[N])
{
	return N;
}

[[gnu::always_inline]]
void bf_test_index(bf_state* state)
{
	if (state->index >= countof(state->memory))
	{
		puts("buffer overflow");
		abort();
	}
}

#define BF_CMD(cmd) [[gnu::noinline]] extern "C" void bf_ ## cmd (bf_state* __restrict__ state)

// commands
BF_CMD(init)
{
	for (unsigned long i = 0; i < countof(state->memory); i++)
	{
		state->memory[i] = 0;
	}
	state->index = 0;
	state->ip = 0;
}

BF_CMD(inc_index)
{
	state->index++;
}

BF_CMD(dec_index)
{
	state->index--;
}

BF_CMD(inc)
{
	bf_test_index(state);
	state->memory[state->index]++;
}

BF_CMD(dec)
{
	bf_test_index(state);
	state->memory[state->index]--;
}

BF_CMD(in)
{
	bf_test_index(state);
	read(0, &state->memory[state->index], 1);
}

BF_CMD(out)
{
	bf_test_index(state);
	write(1, &state->memory[state->index], 1);
}

BF_CMD(enter_scope)
{
	bf_test_index(state);
	if (state->memory[state->index] == 0)
	{
		bf_skip_scope(state);
	}
}

BF_CMD(exit_scope)
{
	bf_test_index(state);
	if (state->memory[state->index] != 0)
	{
		bf_rewind_scope(state);
	}
}
