//
// pass_python.h
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

#ifndef pass_python_hpp
#define pass_python_hpp

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Pass.h>
#include <llvm/Support/ErrorOr.h>
SILENCE_LLVM_WARNINGS_END()

#include <cassert>
#include <memory>
#include <string>

class PythonContext
{
public:
	PythonContext(const std::string& programPath);
	~PythonContext();
	
	llvm::ErrorOr<llvm::Pass*> createPass(const std::string& path);
};

#endif /* pass_python_hpp */
