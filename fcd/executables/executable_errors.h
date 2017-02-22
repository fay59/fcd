//
// executable_errors.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__executables_executable_errors_h
#define fcd__executables_executable_errors_h

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

#endif /* fcd__executables_executable_errors_h */
