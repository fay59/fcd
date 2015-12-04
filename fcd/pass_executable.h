//
// pass_executable.h
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

#ifndef pass_executable_hpp
#define pass_executable_hpp

#include "executable.h"
#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Pass.h>
SILENCE_LLVM_WARNINGS_END()

class ExecutableWrapper : public llvm::ImmutablePass
{
	Executable* executable;
	
public:
	static char ID;
	
	ExecutableWrapper(Executable* executable)
	: llvm::ImmutablePass(ID), executable(executable)
	{
	}
	
	Executable* getExecutable() { return executable; }
};

namespace llvm
{
	template<>
	inline Pass *callDefaultCtor<ExecutableWrapper>() { return nullptr; }
}

#endif /* pass_executable_hpp */
