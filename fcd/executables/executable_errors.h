//
// executable_errors.h
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

#ifndef executable_errors_hpp
#define executable_errors_hpp

#include <string>
#include <system_error>

enum class ExecutableParsingError
{
	Generic_NoError,
	Generic_UnknownFormat,
	
	Elf_Corrupted,
	Elf_EndianMismatch,
	
	FlatBin_EntryPointOutOfRange,
	
	Generic_ErrorMax
};

std::error_code make_error_code(ExecutableParsingError error);

class ExecutableParsingErrorCategory : public std::error_category
{
public:
	static ExecutableParsingErrorCategory& instance();
	
	virtual const char* name() const noexcept override;
	virtual std::string message(int condition) const override;
};

#endif /* executable_errors_hpp */
