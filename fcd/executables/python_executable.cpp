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
				if (PyString_AsStringAndSize(object.get(), &bufferPointer, &stringLength))
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
		virtual bool doGetStubTarget(uint64_t address, string& into) const override
		{
			PyErrClearAtEnd clearPyErrAtEndOfFunction;
			AutoPyObject& stubTargetFunc = const_cast<PythonParsedExecutable*>(this)->getStubTarget;
			auto result = getString(callObject(stubTargetFunc, TAKEREF PyLong_FromUnsignedLong(address)), into);
			
			if (PyErr_Occurred())
			{
				PyErr_Print();
			}
			return result;
		}
		
	public:
		static unique_ptr<PythonParsedExecutable> create(string path, const uint8_t* begin, const uint8_t* end)
		{
			auto moduleOrError = loadModule(path);
			if (!moduleOrError)
			{
				return nullptr;
			}
			
			unique_ptr<PythonParsedExecutable> parsedExecutable(new PythonParsedExecutable(move(path), begin, end));
			parsedExecutable->module = move(moduleOrError.get());
			if (!parsedExecutable->callInitFunction())
			{
				return nullptr;
			}
			
			if (!parsedExecutable->cacheExecutableTypeString())
			{
				return nullptr;
			}
			
			parsedExecutable->getStubTarget = parsedExecutable->getCallable("getStubTarget");
			if (!parsedExecutable->getStubTarget)
			{
				return nullptr;
			}
			
			parsedExecutable->getStubTarget = parsedExecutable->getCallable("mapAddress");
			if (!parsedExecutable->getStubTarget)
			{
				return nullptr;
			}
			
			return parsedExecutable;
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
