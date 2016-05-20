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

#ifndef fcd__python_pass_python_h
#define fcd__python_pass_python_h


#include <llvm/Pass.h>
#include <llvm/Support/ErrorOr.h>

#include <cassert>
#include <memory>
#include <string>

struct _object;

class PythonContext
{
	_object* llvmModule;
	
public:
	PythonContext(const std::string& programPath);
	~PythonContext();
	
	llvm::ErrorOr<llvm::Pass*> createPass(const std::string& path);
};

#endif /* fcd__python_pass_python_h */
