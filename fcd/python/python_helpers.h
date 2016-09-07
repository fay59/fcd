//
// python_helpers.h
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

#ifndef python_helpers_h
#define python_helpers_h

#include <llvm/Support/ErrorOr.h>

#include <Python/Python.h>
#include <memory>
#include <utility>

struct PyErrClearAtEnd
{
	~PyErrClearAtEnd() { PyErr_Clear(); }
};

struct PyDecRef
{
	void operator()(PyObject* obj) const
	{
		Py_XDECREF(obj);
	}
};

typedef std::unique_ptr<PyObject, PyDecRef> AutoPyObject;

// use TAKEREF when you receive a new reference
struct TakeRefWrapWithAutoPyObject
{
	// operator|| is the last operator to have more precedence than operator=
	AutoPyObject operator||(PyObject* that) const
	{
		return AutoPyObject(that);
	}
};

// use ADDREF when you receive a borrowed reference
struct AddRefWrapWithAutoPyObject
{
	AutoPyObject operator||(PyObject* that) const
	{
		if (that != nullptr)
		{
			Py_INCREF(that);
		}
		return AutoPyObject(that);
	}
};

#define TAKEREF TakeRefWrapWithAutoPyObject() ||
#define ADDREF AddRefWrapWithAutoPyObject() ||

int getPythonErrno();
llvm::ErrorOr<AutoPyObject> loadModule(const std::string& path);

inline void addObjectToTuple(AutoPyObject& tuple, size_t index, AutoPyObject& item)
{
	// PyTuple_SET_ITEM steals a reference. Nasty.
	Py_IncRef(item.get());
	PyTuple_SET_ITEM(tuple.get(), index, item.get());
}

inline void addObjectToTuple(AutoPyObject& tuple, size_t index, AutoPyObject&& item)
{
	addObjectToTuple(tuple, index, item);
}

template<typename... T>
void addObjectToTuple(AutoPyObject& tuple, size_t index, AutoPyObject& next, T&&... other)
{
	addObjectToTuple(tuple, index, next);
	addObjectToTuple(tuple, index + 1, std::forward<T>(other)...);
}

template<typename... T>
AutoPyObject makeTuple(T&&... objects)
{
	AutoPyObject tuple = TAKEREF PyTuple_New(sizeof...(T));
	addObjectToTuple(tuple, 0, std::forward<T>(objects)...);
	return tuple;
}

template<typename Callable, typename... T>
AutoPyObject callObject(Callable&& callable, T&&... arguments)
{
	return TAKEREF PyObject_CallObject(callable.get(), makeTuple(std::forward<T>(arguments)...).get());
}

#endif /* python_helpers_hpp */
