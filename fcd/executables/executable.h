//
// executable.h
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

#ifndef ExecutableParser_cpp
#define ExecutableParser_cpp

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/ErrorOr.h>
SILENCE_LLVM_WARNINGS_END()

#include <memory>
#include <string>
#include <vector>

struct SymbolInfo
{
	std::string name;
	uint64_t virtualAddress;
	const uint8_t* memory;
};

class Executable
{
	const uint8_t* dataBegin;
	const uint8_t* dataEnd;
	
protected:
	inline Executable(const uint8_t* begin, const uint8_t* end)
	: dataBegin(begin), dataEnd(end)
	{
	}
	
	virtual std::vector<uint64_t> doGetVisibleEntryPoints() const = 0;
	virtual const SymbolInfo* doGetInfo(uint64_t address) const = 0;
	virtual const std::string* doGetStubTarget(uint64_t address) const = 0;
	
public:
	static llvm::ErrorOr<std::unique_ptr<Executable>> parse(const uint8_t* begin, const uint8_t* end);
	
	inline const uint8_t* begin() const { return dataBegin; }
	inline const uint8_t* end() const { return dataEnd; }
	
	std::vector<uint64_t> getVisibleEntryPoints() const { return doGetVisibleEntryPoints(); }
	const SymbolInfo* getInfo(uint64_t address) const;
	const std::string* getStubTarget(uint64_t address) const { return doGetStubTarget(address); }
	
	virtual ~Executable() = default;
};

#endif /* ExecutableParser_cpp */
