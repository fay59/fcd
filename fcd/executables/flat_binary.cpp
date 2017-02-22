//
// flat_binary.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "command_line.h"
#include "executable_errors.h"
#include "flat_binary.h"

using namespace llvm;
using namespace std;

namespace
{
	cl::opt<uint64_t> flatOrigin("flat-org", cl::desc("Load address of binary (--format=flat)"), whitelist());
	
	class FlatBinary final : public Executable
	{
		uint64_t baseAddress;
		
	protected:
		virtual string doGetTargetTriple() const override
		{
			// Replace x86_64 with a flat-arch option the day that we will support more architectures.
			return "x86_64-unknown-";
		}
		
	public:
		FlatBinary(const uint8_t* begin, const uint8_t* end, uint64_t baseAddress)
		: Executable(begin, end), baseAddress(baseAddress)
		{
		}
		
		virtual string getExecutableType() const override
		{
			return "Flat";
		}
		
		virtual const uint8_t* map(uint64_t address) const override
		{
			auto size = static_cast<size_t>(end() - begin());
			if (address >= baseAddress && address < baseAddress + size)
			{
				return begin() + (address - baseAddress);
			}
			return nullptr;
		}
		
		virtual StubTargetQueryResult doGetStubTarget(uint64_t address, string& libraryName, string& into) const override
		{
			return Unresolved;
		}
	};
}

FlatBinaryExecutableFactory::FlatBinaryExecutableFactory()
: ExecutableFactory("flat", "flat binary")
{
}

ErrorOr<unique_ptr<Executable>> FlatBinaryExecutableFactory::parse(const uint8_t* begin, const uint8_t* end)
{
	unique_ptr<Executable> executable = make_unique<FlatBinary>(begin, end, flatOrigin);
	return move(executable);
}
