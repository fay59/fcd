//
//  ExecutableParser.hpp
//  x86Emulator
//
//  Created by Félix on 2015-07-21.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
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
	static std::pair<const uint8_t*, const uint8_t*> mmap(const std::string& path) throw();
	static std::unique_ptr<Executable> parse(const uint8_t* begin, const uint8_t* end);
	
	inline const uint8_t* begin() const { return dataBegin; }
	inline const uint8_t* end() const { return dataEnd; }
	
	virtual std::vector<uint64_t> getVisibleEntryPoints() const = 0;
	virtual const SymbolInfo* getInfo(uint64_t address) = 0;
	
	virtual ~Executable() = default;
};

#endif /* ExecutableParser_cpp */
