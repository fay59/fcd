//
// python_context.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
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
