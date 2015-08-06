//
//  capstone.cpp
//  x86Emulator
//
//  Created by Félix on 2015-04-20.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <string>
#include <system_error>
#include "capstone_wrapper.h"

using namespace std;

const char* capstone_error_category::name() const noexcept
{
	return "Capstone Error";
}

string capstone_error_category::message(int ev) const
{
	return cs_strerror(static_cast<cs_err>(ev));
}

capstone_error_category capstone_errors;

capstone_iter::capstone_iter()
{
	borrowed_handle = 0;
	memory = nullptr;
	code = nullptr;
	remaining = 0;
	nextAddress = 0;
}

const capstone_iter capstone_iter::end = capstone_iter();

capstone_iter::capstone_iter(csh handle, const uint8_t* code, size_t remaining, uint64_t next_address)
{
	borrowed_handle = handle;
	this->memory = cs_malloc(borrowed_handle);
	this->code = code;
	this->remaining = remaining;
	this->nextAddress = next_address;
}

capstone_iter::capstone_iter(const capstone_iter& that)
{
	borrowed_handle = that.borrowed_handle;
	memory = cs_malloc(borrowed_handle);
	auto detail = memory->detail;
	*memory = *that.memory;
	*detail = *that.memory->detail;
	memory->detail = detail;
	code = that.code;
	remaining = that.remaining;
	nextAddress = that.nextAddress;
}

capstone_iter::capstone_iter(capstone_iter&& that)
{
	borrowed_handle = that.borrowed_handle;
	memory = that.memory;
	that.memory = nullptr;
	code = that.code;
	remaining = that.remaining;
	that.remaining = 0;
	nextAddress = that.nextAddress;
}

capstone_iter::~capstone_iter()
{
	if (memory != nullptr)
	{
		cs_free(memory, 1);
	}
}

bool capstone_iter::is_end()
{
	return remaining == 0;
}

capstone_iter::operation_result capstone_iter::next()
{
	if (remaining == 0)
	{
		return no_more_data;
	}
	
	if (!cs_disasm_iter(borrowed_handle, &code, &remaining, &nextAddress, memory))
	{
		return invalid_data;
	}
	
	return success;
}

capstone::capstone(cs_arch arch, unsigned mode)
{
	cs_err err = cs_open(arch, static_cast<cs_mode>(mode), &handle);
	if (err != CS_ERR_OK)
	{
		error_code code(err, capstone_errors);
		throw system_error(code);
	}
	
	err = cs_option(handle, CS_OPT_DETAIL, true);
	if (err != CS_ERR_OK)
	{
		error_code code(err, capstone_errors);
		throw system_error(code);
	}
}

capstone::~capstone()
{
	cs_close(&handle);
}

capstone_iter capstone::begin(const uint8_t *begin, const uint8_t *end, uint64_t virtual_address)
{
	if (end < begin)
	{
		throw invalid_argument("end");
	}
	return capstone_iter(handle, begin, end - begin, virtual_address);
}
