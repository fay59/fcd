//
// capstone_wrapper.cpp
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

#include <string>
#include <system_error>
#include "capstone_wrapper.h"

using namespace llvm;
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

capstone::capstone(csh handle)
: handle(handle)
{
	assert(handle != 0);
}

ErrorOr<capstone> capstone::create(cs_arch arch, unsigned int mode)
{
	csh handle;
	cs_err err = cs_open(arch, static_cast<cs_mode>(mode), &handle);
	if (err == CS_ERR_OK)
	{
		err = cs_option(handle, CS_OPT_DETAIL, true);
		if (err == CS_ERR_OK)
		{
			capstone cs(handle);
			return ErrorOr<capstone>(move(cs));
		}
	}
	
	error_code code(err, capstone_errors);
	return ErrorOr<capstone>(code);
}

capstone::capstone(capstone&& that)
: handle(that.handle)
{
	that.handle = 0;
}

capstone::~capstone()
{
	cs_close(&handle);
}

capstone::inst_ptr capstone::alloc()
{
	return inst_ptr(cs_malloc(handle));
}

bool capstone::disassemble(cs_insn* into, const uint8_t *begin, const uint8_t *end, uint64_t virtual_address)
{
	size_t size = size_t(end - begin);
	return cs_disasm_iter(handle, &begin, &size, &virtual_address, into) ? true : false;
}

capstone_iter capstone::begin(const uint8_t *begin, const uint8_t *end, uint64_t virtual_address)
{
	if (end < begin)
	{
		assert(false);
		end = begin;
	}
	return capstone_iter(handle, begin, static_cast<size_t>(end - begin), virtual_address);
}
