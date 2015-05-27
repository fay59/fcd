//
//  x86_register_map.cpp
//  x86Emulator
//
//  Created by Félix on 2015-05-04.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <cstring>

#include "x86_register_map.h"
#include "x86_emulator.h"

namespace
{
	union single_register_names {
		struct {
			const char* low_byte;
			const char* high_byte;
			const char* word;
			const char* dword;
			const char* qword;
		};
		const char* names[5];
	};

	#define SINGLE_LETTER_REG(l) { #l "l", #l "h", #l "x", "e" #l "x", "r" #l "x" }
	#define TWO_LETTER_REG(ll) { #ll "l", nullptr, #ll, "e" #ll, "r" #ll }
	#define EXTENDED_REG(n) { "r" #n "b", nullptr, "r" #n "w", "r" #n "d", "r" #n }
	#define SEGMENT_REG(x) { nullptr, nullptr, #x, #x, #x }

	const single_register_names register_map[] = {
		SINGLE_LETTER_REG(z),
		SINGLE_LETTER_REG(a), SINGLE_LETTER_REG(b),
		SINGLE_LETTER_REG(c), SINGLE_LETTER_REG(d),
		TWO_LETTER_REG(si), TWO_LETTER_REG(di),
		TWO_LETTER_REG(bp), TWO_LETTER_REG(sp), TWO_LETTER_REG(ip),
		EXTENDED_REG(8), EXTENDED_REG(9), EXTENDED_REG(10), EXTENDED_REG(11),
		EXTENDED_REG(12), EXTENDED_REG(13), EXTENDED_REG(14), EXTENDED_REG(15),
		SEGMENT_REG(cs), SEGMENT_REG(ds), SEGMENT_REG(es),
		SEGMENT_REG(fs), SEGMENT_REG(gs), SEGMENT_REG(ss),
	};
	
	template<typename T, size_t N>
	constexpr size_t countof(const T (&)[N])
	{
		return N;
	}
}

const char* x86_get_register_name(size_t offset, size_t size)
{
	size_t array_offset = offset / sizeof (x86_qword_reg);
	if (array_offset >= countof(register_map))
	{
		return nullptr;
	}
	const auto& names = register_map[array_offset];
	
	size_t sub_offset = offset - array_offset * sizeof (x86_qword_reg);
	if (sub_offset == 1)
	{
		if (size == 1)
		{
			return names.high_byte;
		}
		return nullptr;
	}
	
	switch (size)
	{
		case 1: return names.low_byte;
		case 2: return names.word;
		case 4: return names.dword;
		case 8: return names.qword;
	}
	
	return nullptr;
}

const char* x86_unique_register_name(const char* name)
{
	for (const auto& regStruct : register_map)
	{
		for (const char* internName : regStruct.names)
		{
			if (internName != nullptr && strcmp(name, internName) == 0)
			{
				return internName;
			}
		}
	}
	return nullptr;
}
