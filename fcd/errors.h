//
// errors.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
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
	Python_ExecutableScriptInitializationError,
	
	MaxError,
};

std::error_code make_error_code(FcdError error);

#endif /* fcd__errors_h */
