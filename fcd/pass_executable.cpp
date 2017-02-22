//
// pass_executable.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "pass_executable.h"

using namespace llvm;
using namespace std;

namespace
{
	RegisterPass<ExecutableWrapper> executableWrapper("#executable-wrapper", "Executable wrapper", false, false);
}

char ExecutableWrapper::ID = 0;
