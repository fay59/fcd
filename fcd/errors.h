//
// errors.h
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

#ifndef fcd__errors_h
#define fcd__errors_h

#include <string>
#include <system_error>

class fcd_error_category : public std::error_category
{
public:
	static fcd_error_category& instance();
	
	virtual const char* name() const noexcept override;
	virtual std::string message(int ev) const override;
};

enum class FcdError
{
	NoError,
	
	Main_EntryPointOutOfMappedMemory,
	Main_NoEntryPoint,
	Main_DecompilationError,
	Main_HeaderParsingError,
	
	Python_LoadError,
	Python_InvalidPassFunction,
	Python_PassTypeConfusion,
	
	MaxError,
};

std::error_code make_error_code(FcdError error);

#endif /* fcd__errors_h */
