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
#include "python_executable.h"

#include <ctype.h>

using namespace llvm;
using namespace std;

namespace
{
	// http://stackoverflow.com/a/2886589/251153
	// "all you have to do"... understatement of the week!
	struct ci_char_traits : public char_traits<char>
	{
		static bool eq(char c1, char c2) { return toupper(c1) == toupper(c2); }
		static bool ne(char c1, char c2) { return toupper(c1) != toupper(c2); }
		static bool lt(char c1, char c2) { return toupper(c1) <  toupper(c2); }
		
		static int compare(const char* s1, const char* s2, size_t n)
		{
			while (n != 0)
			{
				--n;
				if (toupper(*s1) < toupper(*s2))
				{
					return -1;
				}
				if (toupper(*s1) > toupper(*s2))
				{
					return 1;
				}
				++s1;
				++s2;
			}
			return 0;
		}
		
		static const char* find(const char* s, int n, char a)
		{
			while (n > 0 && !eq(*s, a))
			{
				--n;
				++s;
			}
			return s;
		}
	};
	
	typedef basic_string<char, ci_char_traits> ci_string;
	
	const char elf_magic[4] = {0x7f, 'E', 'L', 'F'};
	
	enum ExecutableFormat
	{
		Unknown,
		Auto,
		Elf,
		FlatBinary,
		PythonScript,
	};
	
	cl::opt<ci_string> format("format", cl::value_desc("format"),
		cl::desc("Executable format. Must be \"auto\", \"elf\", \"flat\" or a path to a Python script."),
		cl::init("auto"),
		whitelist()
	);
	
	cl::alias formatA("f", cl::desc("Alias for --format"), cl::aliasopt(format), whitelist());
}

vector<uint64_t> Executable::getVisibleEntryPoints() const
{
	vector<uint64_t> result;
	for (const auto& pair : symbols)
	{
		result.push_back(pair.second.virtualAddress);
	}
	return result;
}

const SymbolInfo* Executable::getInfo(uint64_t address) const
{
	auto iter = symbols.find(address);
	if (iter != symbols.end())
	{
		return &iter->second;
	}
	else if (const uint8_t* memory = map(address))
	{
		SymbolInfo& info = symbols[address];
		info.virtualAddress = address;
		info.memory = memory;
		return &info;
	}
	return nullptr;
}

const string* Executable::getStubTarget(uint64_t address) const
{
	auto iter = stubTargets.find(address);
	if (iter != stubTargets.end())
	{
		return &iter->second;
	}
	
	string result;
	if (doGetStubTarget(address, result))
	{
		string& nameRef = stubTargets[address];
		nameRef = move(result);
		return &nameRef;
	}
	return nullptr;
}

ErrorOr<unique_ptr<Executable>> Executable::parse(const uint8_t* begin, const uint8_t* end)
{
	ExecutableFormat formatAsEnum = Unknown;
	if (format == "auto")
	{
		if (memcmp(begin, elf_magic, sizeof elf_magic) == 0)
		{
			formatAsEnum = Elf;
		}
		else
		{
			formatAsEnum = FlatBinary;
		}
	}
	else if (format == "elf")
	{
		formatAsEnum = Elf;
	}
	else if (format == "flat")
	{
		formatAsEnum = FlatBinary;
	}
	else if (format.length() > 3 && format.compare(format.length() - 3, 3, ".py") == 0)
	{
		formatAsEnum = PythonScript;
	}
	
	switch (formatAsEnum)
	{
		case Elf: return parseElfExecutable(begin, end);
		case FlatBinary: return parseFlatBinary(begin, end);
		case PythonScript: return parseBinaryWithPythonScript(string(format.begin(), format.end()), begin, end);
		default: return make_error_code(ExecutableParsingError::Generic_UnknownFormat);
	}
}
