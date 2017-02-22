//
// python_helpers.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef python_helpers_h
#define python_helpers_h

#include <llvm/Support/ErrorOr.h>

#ifdef __APPLE__
#include <Python/Python.h>
#else
#include <Python.h>
#endif

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
