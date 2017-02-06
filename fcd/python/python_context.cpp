//
// python_context.cpp
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

#include "bindings.h"
#include "errors.h"
#include "python_context.h"
#include "python_helpers.h"

#include <llvm/IR/Module.h>
#include <llvm/Support/Path.h>

#include <Python/Python.h>

using namespace llvm;
using namespace std;

namespace
{
#pragma mark - Wrapper passes
	struct PythonWrapper
	{
		AutoPyObject module;
		AutoPyObject run;
		string name;
		
	public:
		PythonWrapper(AutoPyObject module, AutoPyObject run, const string& name)
		: module(move(module)), run(move(run)), name(name)
		{
		}
		
		bool runWithObject(PyObject* object)
		{
			PyErr_Clear();
			
			auto tupleArg = TAKEREF PyTuple_New(1);
			Py_INCREF(object); // account for ref that PyTuple is about to steal
			PyTuple_SET_ITEM(tupleArg.get(), 0, object);
			auto callResult = TAKEREF PyObject_CallObject(run.get(), tupleArg.get());
			
			if (PyErr_Occurred() != nullptr)
			{
				PyErr_Print();
				// There's no clean way to stop a pass manager, so, um, exit?
				exit(3);
			}
			
			return PyObject_IsTrue(callResult.get());
		}
	};
	
	struct PythonWrappedModule final : public ModulePass, public PythonWrapper
	{
		static char ID;
		
		PythonWrappedModule(PythonWrapper wrapper)
		: ModulePass(ID), PythonWrapper(move(wrapper))
		{
		}
		
		virtual const char* getPassName() const override
		{
			return name.c_str();
		}
		
		virtual bool runOnModule(Module& m) override
		{
			auto pyModuleObject = TAKEREF Py_LLVMModule_Type.tp_alloc(&Py_LLVMModule_Type, 0);
			((Py_LLVM_Wrapped<LLVMModuleRef>*)pyModuleObject.get())->obj = wrap(&m);
			return runWithObject(pyModuleObject.get());
		}
	};
	
	struct PythonWrappedFunction final : public FunctionPass, public PythonWrapper
	{
		static char ID;
		
		PythonWrappedFunction(PythonWrapper wrapper)
		: FunctionPass(ID), PythonWrapper(move(wrapper))
		{
		}
		
		virtual const char* getPassName() const override
		{
			return name.c_str();
		}
		
		virtual bool runOnFunction(Function& fn) override
		{
			auto pyModuleObject = TAKEREF Py_LLVMValue_Type.tp_alloc(&Py_LLVMValue_Type, 0);
			((Py_LLVM_Wrapped<LLVMValueRef>*)pyModuleObject.get())->obj = wrap(&fn);
			return runWithObject(pyModuleObject.get());
		}
	};
	
	char PythonWrappedModule::ID = 0;
	char PythonWrappedFunction::ID = 0;
	
	RegisterPass<PythonWrappedModule> pyModulePass("#py-module-pass", "Python-wrapped module pass", false, false);
	RegisterPass<PythonWrappedFunction> pyFuncPass("#py-function-pass", "Python-wrapped function pass", false, false);
}

#ifdef FCD_DEBUG
// needs external linkage to be available during debugging
void dump(PyObject* obj)
{
	PyObject_Print(obj, stderr, 0);
}
#endif

#pragma mark - Implementation
PythonContext::PythonContext(const string& programPath)
{
	unique_ptr<char, decltype(free)&> mutableName(strdup(programPath.c_str()), free);
	Py_SetProgramName(mutableName.get());
	Py_Initialize();
	
	initLlvmModule(&llvmModule);
}

ErrorOr<Pass*> PythonContext::createPass(const std::string &path)
{
	auto moduleOrError = loadModule(path);
	if (!moduleOrError)
	{
		return moduleOrError.getError();
	}
	
	auto& module = moduleOrError.get();
	auto runOnModule = TAKEREF PyObject_GetAttrString(module.get(), "runOnModule");
	auto runOnFunction = TAKEREF PyObject_GetAttrString(module.get(), "runOnFunction");
	PyErr_Clear();
	
	unique_ptr<string> passName;
	if (auto passNameObj = TAKEREF PyObject_GetAttrString(module.get(), "passName"))
	if (auto asString = TAKEREF PyObject_Str(passNameObj.get()))
	{
		char* bufferPointer;
		Py_ssize_t stringLength;
		if (PyString_AsStringAndSize(asString.get(), &bufferPointer, &stringLength) == 0)
		{
			passName.reset(new string(bufferPointer, static_cast<size_t>(stringLength)));
		}
	}
	
	if (runOnModule)
	{
		if (runOnFunction)
		{
			return make_error_code(FcdError::Python_PassTypeConfusion);
		}
		
		if (!PyCallable_Check(runOnModule.get()))
		{
			return make_error_code(FcdError::Python_InvalidPassFunction);
		}
		
		if (!passName)
		{
			passName.reset(new string("Python Module Pass"));
		}
		
		PythonWrapper wrapper(move(module), move(runOnModule), move(*passName));
		return new PythonWrappedModule(move(wrapper));
	}
	else if (runOnFunction)
	{
		if (!PyCallable_Check(runOnFunction.get()))
		{
			return make_error_code(FcdError::Python_InvalidPassFunction);
		}
		
		if (!passName)
		{
			passName.reset(new string("Python Function Pass"));
		}
		
		PythonWrapper wrapper(move(module), move(runOnFunction), move(*passName));
		return new PythonWrappedFunction(move(wrapper));
	}
	else
	{
		return make_error_code(FcdError::Python_PassTypeConfusion);
	}
	
	return nullptr;
}

PythonContext::~PythonContext()
{
	Py_Finalize();
}

namespace llvm
{
	// These shouldn't be called.
	template<>
	Pass* callDefaultCtor<PythonWrappedModule>()
	{
		assert(false);
		return nullptr;
	}
	
	template<>
	Pass* callDefaultCtor<PythonWrappedFunction>()
	{
		assert(false);
		return nullptr;
	}
}
