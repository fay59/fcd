//
// python_helpers.cpp
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

#include "errors.h"
#include "python_helpers.h"

#include <llvm/Support/Path.h>

using namespace llvm;
using namespace std;

int getPythonErrno()
{
	// Make reasonable efforts to find errno, or 0 otherwise.
	PyObject* unmanagedType;
	PyObject* unmanagedData;
	PyObject* unmanagedBt;
	PyErr_Fetch(&unmanagedType, &unmanagedData, &unmanagedBt);
	if (auto managedType = ADDREF unmanagedType)
	if (auto managedData = ADDREF unmanagedData)
	if (PyErr_GivenExceptionMatches(managedType.get(), PyExc_EnvironmentError))
	if (auto errorField = ADDREF PyTuple_GetItem(managedData.get(), 0))
	{
		long errorNumber = PyInt_AsLong(errorField.get());
		if (errorNumber != -1 || PyErr_Occurred() == nullptr)
		{
			return static_cast<int>(errorNumber);
		}
	}
	return 0;
}

ErrorOr<AutoPyObject> loadModule(const std::string& path)
{
	PyErrClearAtEnd clearPyErrAtEndOfFunction;
	
	// Like the official CPython source, use the imp module to load files by path.
	auto modules = ADDREF PyImport_GetModuleDict();
	auto impModule = ADDREF PyDict_GetItemString(modules.get(), "imp");
	if (!impModule)
	{
		impModule = TAKEREF PyImport_ImportModule("imp");
		if (!impModule)
		{
			// we've tried hard enough, bail out
			PyErr_Print();
			return make_error_code(FcdError::Python_LoadError);
		}
	}
	
	char methodName[] = "load_source";
	char argSpecifier[] = "ss";
	auto moduleName = sys::path::stem(path).str();
	auto module = TAKEREF PyObject_CallMethod(impModule.get(), methodName, argSpecifier, moduleName.c_str(), path.c_str());
	
	if (module)
	{
		return move(module);
	}
	else if (int error = getPythonErrno())
	{
		return error_code(error, system_category());
	}
	else
	{
		return make_error_code(FcdError::Python_LoadError);
	}
}
