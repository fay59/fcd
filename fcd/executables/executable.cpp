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

#include "command_line.h"
#include "executable.h"
#include "executable_errors.h"
#include "elf_executable.h"
#include "flat_binary.h"
#include "llvm_warnings.h"

#include <unistd.h>

using namespace llvm;
using namespace std;

namespace
{
	const char elf_magic[4] = {0x7f, 'E', 'L', 'F'};
	
	enum ExecutableFormat
	{
		Auto,
		Elf,
		FlatBinary,
	};
	
	cl::opt<ExecutableFormat> format("format", cl::desc("Executable format"), cl::value_desc("format"),
		cl::init(Auto),
		cl::values(
			clEnumValN(Auto, "auto", "autodetect"),
			clEnumValN(Elf, "elf", "ELF"),
			clEnumValN(FlatBinary, "flat", "flat binary"),
			clEnumValEnd
		),
		whitelist()
	);
	
	cl::alias formatA("f", cl::desc("Alias for --format"), cl::aliasopt(format));
}

const SymbolInfo* Executable::getInfo(uint64_t address) const
{
	auto info = doGetInfo(address);
	if (info != nullptr)
	{
		assert(info->memory >= dataBegin && info->memory < dataEnd);
	}
	return info;
}

ErrorOr<unique_ptr<Executable>> Executable::parse(const uint8_t* begin, const uint8_t* end)
{
	if (format == Auto)
	{
		if (memcmp(begin, elf_magic, sizeof elf_magic) == 0)
		{
			format = Elf;
		}
		else
		{
			format = FlatBinary;
		}
	}
	
	if (format == Elf)
	{
		return parseElfExecutable(begin, end);
	}
	else if (format == FlatBinary)
	{
		return parseFlatBinary(begin, end);
	}
	
	return make_error_code(ExecutableParsingError::Generic_UnknownFormat);
}
