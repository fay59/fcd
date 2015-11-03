//
// pass_executable.cpp
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

#include "pass_executable.h"

using namespace llvm;
using namespace std;

namespace
{
<<<<<<< HEAD
	RegisterPass<ExecutableWrapper> executableWrapper("--executable-wrapper", "Executable wrapper", false, false);
=======
	RegisterPass<ExecutableWrapper> pyModulePass("--executable-wrapper", "Executable wrapper", false, false);
>>>>>>> 6c29510e68cc92d42a9c8f763800297d9782de24
}

char ExecutableWrapper::ID = 0;
