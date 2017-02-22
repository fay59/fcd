//
// bindings.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__python_bindings_h
#define fcd__python_bindings_h

#include "python_helpers.h"

#include <memory>

template<typename WrappedType>
struct Py_LLVM_Wrapped
{
	PyObject_HEAD
	WrappedType obj;
};

PyMODINIT_FUNC initLlvmModule(PyObject** module);

extern PyTypeObject Py_LLVMUse_Type;
extern PyTypeObject Py_LLVMModuleProvider_Type;
extern PyTypeObject Py_LLVMBuilder_Type;
extern PyTypeObject Py_LLVMValue_Type;
extern PyTypeObject Py_LLVMPassRegistry_Type;
extern PyTypeObject Py_LLVMPassManager_Type;
extern PyTypeObject Py_LLVMModule_Type;
extern PyTypeObject Py_LLVMContext_Type;
extern PyTypeObject Py_LLVMDiagnosticInfo_Type;
extern PyTypeObject Py_LLVMBasicBlock_Type;
extern PyTypeObject Py_LLVMType_Type;

#endif /* fcd__python_bindings_h */
