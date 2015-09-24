//
// errors.cpp
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

#include "errors.h"

using namespace std;

namespace
{
	template<typename T, size_t N>
	constexpr size_t countof(T (&)[N])
	{
		return N;
	}
	
#define ERROR_MESSAGE(code, message) [static_cast<size_t>(FcdError::code)] = message
	string errorMessages[] = {
		ERROR_MESSAGE(Main_EntryPointOutOfMappedMemory, "additional entry address points outside of executable"),
	};
	
	static_assert(countof(errorMessages) == static_cast<size_t>(FcdError::MaxError), "missing error strings");
	
	fcd_error_category instance;
}

std::error_code make_error_code(FcdError error)
{
	return error_code((int)error, fcd_error_category::instance());
}

fcd_error_category& fcd_error_category::instance()
{
	return ::instance;
}

const char* fcd_error_category::name() const noexcept
{
	return "fcd error";
}

string fcd_error_category::message(int condition) const
{
	if (condition >= static_cast<int>(FcdError::MaxError))
	{
		return "unknown error";
	}
	
	return errorMessages[condition];
}
