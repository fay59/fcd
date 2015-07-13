//
//  dumb_allocator.hpp
//  x86Emulator
//
//  Created by Félix on 2015-06-29.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#ifndef dumb_allocator_cpp
#define dumb_allocator_cpp

#include <algorithm>
#include <cassert>
#include <list>
#include <memory>
#include <type_traits>

// This class provides a fast, stack-like allocation mechanism. It's a lot faster than using a raw `new` for every
// small object we create, and a lot easier to manage: since the objects are enforced to be trivially destructible,
// we can just deallocate everything in bulk.
// On the other hand, it can lead to a small amount of wasted memory (though that should be much much smaller than
// the equivalent overhead would we be to allocate everything with `new`).
template<size_t DefaultPageSize = 0x1000 - 0x20>
class DumbAllocator
{
	static constexpr size_t HalfPageSize = DefaultPageSize / 2;
	
	std::list<std::unique_ptr<char[]>> pool;
	size_t offset;
	
	inline char* allocateSmall(size_t size)
	{
		if (offset < size)
		{
			pool.emplace_back(new char[DefaultPageSize]);
			offset = DefaultPageSize;
		}
		
		offset -= size;
		return &pool.back()[offset];
	}
	
	inline char* allocateLarge(size_t size)
	{
		pool.emplace_front(new char[size]);
		return pool.front().get();
	}
	
public:
	inline DumbAllocator() : offset(0)
	{
	}
	
	DumbAllocator(const DumbAllocator&) = delete;
	
	inline void clear()
	{
		pool.clear();
		offset = 0;
	}
	
	template<typename T, typename... TParams>
	typename std::enable_if<sizeof(T) < HalfPageSize && std::is_trivially_destructible<T>::value, T>::type*
	allocate(TParams&&... params)
	{
		char* address = allocateSmall(sizeof (T));
		return new (address) T(params...);
	}
	
	template<typename T, typename... TParams>
	typename std::enable_if<sizeof(T) >= HalfPageSize && std::is_trivially_destructible<T>::value, T>::type*
	allocate(TParams&&... params)
	{
		char* address = allocateLarge(sizeof (T));
		return new (address) T(params...);
	}
	
	template<typename T>
	T* allocateDynamic(size_t count = 1)
	{
		size_t totalSize;
		if (__builtin_umull_overflow(count, sizeof(T), &totalSize))
		{
			assert(false);
			return nullptr;
		}
		
		if (DefaultPageSize - offset < totalSize || totalSize < HalfPageSize)
		{
			return new (allocateSmall(totalSize)) T[count];
		}
		return new (allocateLarge(totalSize)) T[count];
	}
	
	template<typename T>
	T* copy(T* origin, size_t count)
	{
		if (auto memory = allocateDynamic<typename std::remove_cv<T>::type>(count))
		{
			std::copy(origin, origin + count, memory);
			return memory;
		}
		return nullptr;
	}
};

#endif /* dumb_allocator_cpp */
