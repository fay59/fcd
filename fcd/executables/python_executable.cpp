//
// python_executable.cpp
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
#include "python_executable.h"
#include "python_helpers.h"

#include <llvm/Support/raw_ostream.h>

#include <unordered_map>

// We assume here that Python has already been initialized (most likely with a PythonContext).

using namespace llvm;
using namespace std;

namespace
{
	class PythonParsedExecutable : public Executable
	{
		string path;
		string executableType;
		
		AutoPyObject module;
		AutoPyObject getStubTarget;
		AutoPyObject mapAddress;
		
		static bool getString(AutoPyObject&& object, string& output)
		{
			if (object)
			{
				char* bufferPointer;
				Py_ssize_t stringLength;
				if (PyString_AsStringAndSize(object.get(), &bufferPointer, &stringLength) == 0)
				{
					output = string(bufferPointer, stringLength);
					return true;
				}
			}
			return false;
		}
		
		PythonParsedExecutable(string path, const uint8_t* begin, const uint8_t* end)
		: Executable(begin, end), path(move(path))
		{
		}
		
		bool callInitFunction()
		{
			PyErrClearAtEnd clearPyErrAtEndOfFunction;
			
			auto init = getCallable("init");
			auto bytes = TAKEREF PyString_FromStringAndSize(reinterpret_cast<const char*>(begin()), end() - begin());
			callObject(init, bytes);
			
			if (PyErr_Occurred())
			{
				errs() << "Script " << path << " failed to initialize properly!\n";
				PyErr_Print();
				PyErr_Clear();
				return false;
			}
			return true;
		}
		
		bool cacheExecutableTypeString()
		{
			PyErrClearAtEnd clearPyErrAtEndOfFunction;
			
			if (getString(TAKEREF PyObject_GetAttrString(module.get(), "executableType"), executableType))
			{
				return true;
			}
			errs() << "Script " << path << " does not expose a string-typed executableType!\n";
			return false;
		}
		
		bool cacheEntryPoints()
		{
			PyErrClearAtEnd clearPyErrAtEndOfFunction;
			
			if (auto entryPoints = TAKEREF PyObject_GetAttrString(module.get(), "entryPoints"))
			if (auto sequence = TAKEREF PySequence_Fast(entryPoints.get(), nullptr))
			{
				Py_ssize_t len = PySequence_Length(sequence.get());
				for (Py_ssize_t i = 0; i < len; ++i)
				{
					auto element = TAKEREF PySequence_Fast(PySequence_Fast_GET_ITEM(sequence.get(), i), nullptr);
					if (!element)
					{
						errs() << "Symbol entry " << i << " is not a sequence!\n";
						return false;
					}
					if (PySequence_Length(element.get()) != 2)
					{
						errs() << "Symbol entry " << i << " does not follow format (address, name)!\n";
						return false;
					}
					
					string symbolName;
					if (!getString(ADDREF PySequence_Fast_GET_ITEM(element.get(), 1), symbolName))
					{
						errs() << "Symbol entry " << i << " does not follow format (address, name)!\n";
						return false;
					}
					
					auto addressObject = ADDREF PySequence_Fast_GET_ITEM(element.get(), 0);
					auto longAddress = callObject(ADDREF reinterpret_cast<PyObject*>(&PyLong_Type), addressObject);
					if (PyErr_Occurred())
					{
						PyErr_Print();
						return false;
					}
					
					unsigned long long address = PyLong_AsUnsignedLongLong(longAddress.get());
					if (PyErr_Occurred())
					{
						PyErr_Print();
						return false;
					}
					
					if (const uint8_t* memory = map(address))
					{
						auto& symbol = getSymbol(address);
						symbol.name = move(symbolName);
						symbol.virtualAddress = address;
						symbol.memory = memory;
					}
					else
					{
						return false;
					}
				}
				return true;
			}
			
			errs() << "Script " << path << " does not expose a sequence-typed entryPoints!\n";
			return false;
		}
		
		AutoPyObject getCallable(const string& name)
		{
			PyErrClearAtEnd clearPyErrAtEndOfFunction;
			
			auto callable = TAKEREF PyObject_GetAttrString(module.get(), name.c_str());
			if (!callable)
			{
				errs() << "Script " << path << " doesn't expose a " << name << " function!\n";
				return nullptr;
			}
			
			if (!PyCallable_Check(callable.get()))
			{
				errs() << "Script " << path << "'s " << name << " is not callable!\n";
				return nullptr;
			}
			
			return callable;
		}
		
	protected:
		virtual StubTargetQueryResult doGetStubTarget(uint64_t address, string& library, string& symbolName) const override
		{
			PyErrClearAtEnd clearPyErrAtEndOfFunction;
			AutoPyObject& stubTargetFunc = const_cast<PythonParsedExecutable*>(this)->getStubTarget;
			auto resultTuple = callObject(stubTargetFunc, TAKEREF PyLong_FromUnsignedLong(address));
			if (PyErr_Occurred())
			{
				PyErr_Print();
				return Unresolved;
			}
			
			if (!PySequence_Check(resultTuple.get()) || PySequence_Size(resultTuple.get()) != 2)
			{
				if (resultTuple.get() != Py_None)
				{
					errs() << "Object returned by getStubTarget is not a list of two items!\n";
				}
				return Unresolved;
			}
			
			AutoPyObject first = TAKEREF PySequence_GetItem(resultTuple.get(), 0);
			if (PyErr_Occurred())
			{
				PyErr_Print();
				return Unresolved;
			}
			
			StubTargetQueryResult resolutionType;
			if (first.get() == Py_None)
			{
				resolutionType = ResolvedInFlatNamespace;
			}
			else if (getString(move(first), library))
			{
				resolutionType = ResolvedInTwoLevelNamespace;
			}
			else
			{
				errs() << "First element returned by getStubTarget(0x";
				errs().write_hex(address);
				errs() << ") is not a string!\n";
				return Unresolved;
			}
			
			AutoPyObject second = TAKEREF PySequence_GetItem(resultTuple.get(), 1);
			if (PyErr_Occurred())
			{
				PyErr_Print();
				return Unresolved;
			}
			
			if (!getString(move(second), symbolName))
			{
				errs() << "Second element returned by getStubTarget(0x";
				errs().write_hex(address);
				errs() << ") is not a string!\n";
				return Unresolved;
			}
			
			return resolutionType;
		}
		
	public:
		static ErrorOr<unique_ptr<PythonParsedExecutable>> create(string path, const uint8_t* begin, const uint8_t* end)
		{
			auto moduleOrError = loadModule(path);
			if (!moduleOrError)
			{
				if (PyErr_Occurred())
				{
					PyErr_Print();
					PyErr_Clear();
				}
				return moduleOrError.getError();
			}
			
			unique_ptr<PythonParsedExecutable> parsedExecutable(new PythonParsedExecutable(move(path), begin, end));
			parsedExecutable->module = move(moduleOrError.get());
			if (!parsedExecutable->callInitFunction())
			{
				return make_error_code(FcdError::Python_ExecutableScriptInitializationError);
			}
			
			if (!parsedExecutable->cacheExecutableTypeString())
			{
				return make_error_code(FcdError::Python_ExecutableScriptInitializationError);
			}
			
			parsedExecutable->getStubTarget = parsedExecutable->getCallable("getStubTarget");
			if (!parsedExecutable->getStubTarget)
			{
				return make_error_code(FcdError::Python_ExecutableScriptInitializationError);
			}
			
			parsedExecutable->mapAddress = parsedExecutable->getCallable("mapAddress");
			if (!parsedExecutable->getStubTarget)
			{
				return make_error_code(FcdError::Python_ExecutableScriptInitializationError);
			}
			
			if (!parsedExecutable->cacheEntryPoints())
			{
				return make_error_code(FcdError::Python_ExecutableScriptInitializationError);
			}
			
			return move(parsedExecutable);
		}
		
		virtual std::string getExecutableType() const override
		{
			return executableType;
		}
		
		virtual const uint8_t* map(uint64_t address) const override
		{
			PyErrClearAtEnd clearPyErrAtEndOfFunction;
			AutoPyObject& mapAddressFunc = const_cast<PythonParsedExecutable*>(this)->mapAddress;
			auto offset = callObject(mapAddressFunc, TAKEREF PyLong_FromUnsignedLong(address));
			if (PyErr_Occurred())
			{
				PyErr_Print();
				return nullptr;
			}
			
			if (offset.get() == Py_None)
			{
				return nullptr;
			}
			
			unsigned long long intOffset = PyLong_AsUnsignedLongLong(offset.get());
			if (PyErr_Occurred())
			{
				PyErr_Print();
				return nullptr;
			}
			
			if (intOffset > end() - begin())
			{
				errs() << "Python script " << path
					<< "'s mapAddress function returned out-of-bounds offset " << intOffset
					<< " for virtual address 0x";
				errs().write_hex(address) << "!\n";
				return nullptr;
			}
			
			return begin() + intOffset;
		}
		
		virtual ~PythonParsedExecutable() = default;
	};
}

PythonExecutableFactory::PythonExecutableFactory()
: ExecutableFactory("*.py", "load executable using specified Python script")
{
}
				
ErrorOr<unique_ptr<Executable>> PythonExecutableFactory::parse(const uint8_t* begin, const uint8_t* end)
{
	return PythonParsedExecutable::create(scriptPath, begin, end);
}
