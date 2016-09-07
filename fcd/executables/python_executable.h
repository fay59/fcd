//
// python_executable.h
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

#ifndef python_executable_h
#define python_executable_h

#include "executable.h"

#include <string>

class PythonExecutableFactory : public ExecutableFactory
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
