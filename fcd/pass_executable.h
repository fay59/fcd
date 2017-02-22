//
// pass_executable.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__pass_executable_h
#define fcd__pass_executable_h

#include "executable.h"

#include <llvm/Pass.h>

class ExecutableWrapper final : public llvm::ImmutablePass
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

#endif /* fcd__pass_executable_h */
