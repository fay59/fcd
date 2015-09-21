//
// flat_binary.cpp
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
#include "executable_errors.h"
#include "flat_binary.h"
#include "llvm_warnings.h"

using namespace llvm;
using namespace std;

namespace
{
	cl::OptionCategory flatBinaryCat("Flat Binary loading", "These control flat binary loading parameters. Only useful with --format=flat.");
	cl::opt<uint64_t> flatOrigin("flat-org", cl::desc("Load address of binary"), cl::value_desc("address"), cl::cat(flatBinaryCat), whitelist());
	cl::opt<uint64_t> flatEntry("flat-entry", cl::desc("Address of flat binary entry point (default: same as load address)"), cl::value_desc("address"), cl::cat(flatBinaryCat), whitelist());
	
	class FlatBinary : public Executable
	{
		SymbolInfo symbol;
		
	public:
		FlatBinary(const uint8_t* begin, const uint8_t* end, uint64_t virtualAddress, uint64_t entryOffset)
		: Executable(begin, end)
		{
			symbol.name = "main";
			symbol.virtualAddress = virtualAddress + entryOffset;
			symbol.memory = begin + entryOffset;
		}
		
		virtual vector<uint64_t> doGetVisibleEntryPoints() const override
		{
			return { flatEntry };
		}
		
		virtual const SymbolInfo* doGetInfo(uint64_t address) const override
		{
			return address == flatEntry ? &symbol : nullptr;
		}
		
		virtual const std::string* doGetStubTarget(uint64_t address) const override
		{
			return nullptr;
		}
	};
}

ErrorOr<unique_ptr<Executable>> parseFlatBinary(const uint8_t* begin, const uint8_t* end)
{
	uint64_t lowerBound = flatOrigin;
	uint64_t upperBound = lowerBound + end - begin;
	uint64_t entryPoint = flatEntry.getPosition() == 0 ? flatOrigin : flatEntry;
	if (entryPoint < lowerBound || entryPoint >= upperBound)
	{
		return make_error_code(ExecutableParsingError::FlatBin_EntryPointOutOfRange);
	}
	
	unique_ptr<Executable> executable = make_unique<FlatBinary>(begin, end, flatOrigin, entryPoint - lowerBound);
	return move(executable);
}
