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
	
public:
	static std::unique_ptr<Executable> parse(const uint8_t* begin, const uint8_t* end);
	
	inline const uint8_t* begin() const { return dataBegin; }
	inline const uint8_t* end() const { return dataEnd; }
	
	virtual std::vector<uint64_t> getVisibleEntryPoints() const = 0;
	virtual const SymbolInfo* getInfo(uint64_t address) = 0;
	virtual const std::string* getStubTarget(uint64_t address) = 0;
	
	virtual ~Executable() = default;
};

#endif /* ExecutableParser_cpp */
