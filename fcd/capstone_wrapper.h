//
//  capstone.h
//  x86Emulator
//
//  Created by Félix on 2015-04-20.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __x86Emulator__capstone__
#define __x86Emulator__capstone__

#include <system_error>
#include "Capstone.h"

class capstone_error_category : public std::error_category
{
public:
	virtual const char* name() const noexcept override;
	virtual std::string message(int ev) const override;
};

class capstone_iter
{
	csh borrowed_handle;
	cs_insn* memory;
	const uint8_t* code;
	size_t remaining;
	uint64_t nextAddress;
	
	bool is_end();
	
	capstone_iter();
	
public:
	enum operation_result
	{
		success,
		no_more_data,
		invalid_data,
	};
	
	capstone_iter(csh handle, const uint8_t* code, size_t remaining, uint64_t next_address);
	capstone_iter(const capstone_iter& that);
	capstone_iter(capstone_iter&& that);
	~capstone_iter();
	
	static const capstone_iter end;
	
	inline uint64_t next_address() { return nextAddress; }
	
	inline cs_insn& operator*() { return *memory; }
	inline cs_insn* operator->() { return memory; }
	
	operation_result next();
};

class capstone
{
	csh handle;
	
public:
	capstone(cs_arch arch, unsigned mode);
	~capstone();
	
	capstone_iter begin(const uint8_t* begin, const uint8_t* end, uint64_t virtual_address = 0);
};

#endif /* defined(__x86Emulator__capstone__) */
