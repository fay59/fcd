//
// not_null.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__not_null_h
#define fcd__not_null_h


#include <llvm/Support/Casting.h>

#ifdef FCD_DEBUG

// Smart pointer class to enforce that the pointer isn't null, and yell loudly if it is.
template<typename T>
struct NotNull
{
	friend class DumbAllocator;
	
	T* ptr;
	
	NotNull(T* ptr) : ptr(ptr)
	{
		assert(ptr);
	}
	
	NotNull(const NotNull<T>& that) = default;
	NotNull(NotNull<T>&& that) = default;
	
	NotNull<T>& operator=(const NotNull<T>& that)
	{
		assert(that.ptr != nullptr); // in case it's a default-constructed NotNull
		ptr = that.ptr;
		return *this;
	}
	
	NotNull<T>& operator=(T* p)
	{
		assert(p);
		this->ptr = p;
		return *this;
	}
	
	T* operator->() const
	{
		return ptr;
	}
	
	T& operator*() const
	{
		return *ptr;
	}
	
	operator T*() const
	{
		return ptr;
	}
	
private:
	// DumbAllocator is allowed to use the default constructor, which creates a null.
	// This is so that it can create an array for PooledDeque.
	NotNull() : ptr(nullptr)
	{
	}
};

template<typename T>
struct llvm::simplify_type<NotNull<T>>
{
	typedef T* SimpleType;
	
	static SimpleType& getSimplifiedValue(NotNull<T>& that)
	{
		return that.ptr;
	}
};

#define NOT_NULL(T) NotNull<T>

template<typename T>
inline T** addressOf(NOT_NULL(T)& x)
{
	return &x.ptr;
}

#else

#define NOT_NULL(T) T*

template<typename T>
inline T** addressOf(NOT_NULL(T)& x)
{
	return &x;
}

#endif

#endif /* fcd__not_null_h */
