//
// flat_binary.cpp
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

#include "flat_binary.h"
#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/CommandLine.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

namespace
{
	cl::OptionCategory flatBinaryCat("Flat Binary loading", "These control flat binary loading parameters. Only useful with --format=flat.");
	cl::opt<uint64_t> flatOrigin("flat-org", cl::desc("Flat binary load offset"), cl::value_desc("offset"), cl::cat(flatBinaryCat));
	cl::opt<uint64_t> flatEntry("flat-entry", cl::desc("Virtual address of flat binary entry point (default: same as load offset)"), cl::value_desc("offset"), cl::cat(flatBinaryCat));
	
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

unique_ptr<Executable> parseFlatBinary(const uint8_t* begin, const uint8_t* end)
{
	uint64_t lowerBound = flatOrigin;
	uint64_t upperBound = lowerBound + end - begin;
	uint64_t entryPoint = flatEntry.getPosition() == 0 ? flatOrigin : flatEntry;
	if (entryPoint < lowerBound || entryPoint >= upperBound)
	{
		return nullptr;
	}
	
	return make_unique<FlatBinary>(begin, end, flatOrigin, entryPoint - lowerBound);
}
