//
// executable.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is part of fcd. fcd as a whole is licensed under the terms
// of the GNU GPLv3 license, but specific parts (such as this one) are
// dual-licensed under the terms of a BSD-like license as well. You
// may use, modify and distribute this part of fcd under the terms of
// either license, at your choice. See the LICENSE file in this directory
// for details.
//

#include "executable.h"
#include "elf_executable.h"

#include <unistd.h>

using namespace std;

namespace
{
	const char elf_magic[4] = {0x7f, 'E', 'L', 'F'};
}

std::unique_ptr<Executable> Executable::parse(const uint8_t* begin, const uint8_t* end)
{
	if (end < begin || end - begin < 4)
	{
		return nullptr;
	}
	
	if (memcmp(begin, elf_magic, sizeof elf_magic) == 0)
	{
		// ELF file
		return parseElfExecutable(begin, end);
	}
	
	return nullptr;
}
