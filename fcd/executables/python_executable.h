//
// python_executable.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef python_executable_h
#define python_executable_h

#include "executable.h"

#include <string>

class PythonExecutableFactory final : public ExecutableFactory
{
	std::string scriptPath;
	
public:
	PythonExecutableFactory();
	
	void setScriptPath(std::string path)
	{
		scriptPath = std::move(path);
	}
	
	virtual llvm::ErrorOr<std::unique_ptr<Executable>> parse(const uint8_t* begin, const uint8_t* end) override;
};

#endif /* python_executable_hpp */
