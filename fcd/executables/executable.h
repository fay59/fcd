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

#ifndef fcd__executables_executable_h
#define fcd__executables_executable_h

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/ErrorOr.h>
SILENCE_LLVM_WARNINGS_END()

#include <memory>
#include <string>
#include <unordered_map>
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
	mutable std::unordered_map<uint64_t, SymbolInfo> symbols;
	
protected:
	inline Executable(const uint8_t* begin, const uint8_t* end)
	: dataBegin(begin), dataEnd(end)
	{
	}
	
	SymbolInfo& getSymbol(uint64_t address) { return symbols[address]; }
	void eraseSymbol(uint64_t address) { symbols.erase(address); }
	
	virtual const std::string* doGetStubTarget(uint64_t address) const = 0;
	
public:
	static llvm::ErrorOr<std::unique_ptr<Executable>> parse(const uint8_t* begin, const uint8_t* end);
	
	virtual std::string getExecutableType() const = 0;
	
	inline const uint8_t* begin() const { return dataBegin; }
	inline const uint8_t* end() const { return dataEnd; }
	
	virtual const uint8_t* map(uint64_t address) const = 0;
	
	std::vector<uint64_t> getVisibleEntryPoints() const;
	const SymbolInfo* getInfo(uint64_t address) const;
	const std::string* getStubTarget(uint64_t address) const { return doGetStubTarget(address); }
	
	virtual ~Executable() = default;
};

#endif /* fcd__executables_executable_h */
