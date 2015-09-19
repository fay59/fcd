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
	cl::opt<uint64_t> flatOffset("flat-offset", cl::desc("Flat binary offset"), cl::value_desc("offset"), cl::init(0));
	
	class FlatBinary : public Executable
	{
		SymbolInfo symbol;
		
	public:
		FlatBinary(const uint8_t* begin, const uint8_t* end)
		: Executable(begin, end)
		{
			symbol.name = "main";
			symbol.virtualAddress = flatOffset;
			symbol.memory = begin;
		}
		
		virtual vector<uint64_t> getVisibleEntryPoints() const override
		{
			return { flatOffset };
		}
		
		virtual const SymbolInfo* getInfo(uint64_t address) override
		{
			return address == flatOffset ? &symbol : nullptr;
		}
		
		virtual const std::string* getStubTarget(uint64_t address) override
		{
			return nullptr;
		}
	};
}

unique_ptr<Executable> parseFlatBinary(const uint8_t* begin, const uint8_t* end)
{
	return make_unique<FlatBinary>(begin, end);
}
