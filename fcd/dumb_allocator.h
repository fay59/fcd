//
// not_null.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__dumb_allocator_h
#define fcd__dumb_allocator_h


#include <llvm/ADT/StringRef.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <iterator>
#include <list>
#include <memory>
#include <cstring>
#include <type_traits>

#include <iostream>

// This class provides a fast, stack-like allocation mechanism. It's a lot faster than using a raw `new` for every
// small object we create, and a lot easier to manage: since the objects are enforced to be trivially destructible,
// we can just deallocate everything in bulk.
// On the other hand, it can lead to a small amount of wasted memory (though that should be much much smaller than
// the equivalent overhead would we be to allocate everything with `new`).
class DumbAllocator
{
	static constexpr size_t DefaultChunkSize = 0x4000 - 0x20;
	static constexpr size_t HalfPageSize = DefaultChunkSize / 2;
	
	std::list<std::unique_ptr<char[]>> pool;
	size_t offset;
	
	inline char* allocateSmall(size_t size, size_t alignment)
	{
		auto& lastPage = pool.back();
		uintptr_t endOffset = reinterpret_cast<uintptr_t>(&lastPage[offset]);
		size_t realSize = size + ((endOffset - size) & (alignment - 1));
		
		if (offset < realSize)
		{
			char* bytes = new char[DefaultChunkSize];
			pool.emplace_back(bytes);
			offset = DefaultChunkSize;
			
			endOffset = reinterpret_cast<uintptr_t>(&bytes[offset]);
			realSize = size + ((endOffset - size) & (alignment - 1));
			assert(realSize <= offset);
		}
		
		offset -= realSize;
		char* result = &pool.back()[offset];
		assert((reinterpret_cast<uintptr_t>(result) & (alignment - 1)) == 0);
		return result;
	}
	
	inline char* allocateLarge(size_t size, size_t alignment)
	{
		if (size == 0 || alignment == 0)
		{
			return nullptr;
		}
		
		size_t requiredSize;
		if (__builtin_add_overflow(size, alignment - 1, &requiredSize))
		{
			return nullptr;
		}
		
		pool.emplace_front(new char[requiredSize]);
		void* bytes = pool.front().get();
		std::align(alignment, requiredSize, bytes, size);
		return static_cast<char*>(bytes);
	}
	
public:
	inline DumbAllocator() : offset(0)
	{
		pool.push_back(nullptr);
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
		char* address = allocateSmall(sizeof(T), alignof(T));
		return new (address) T(params...);
	}
	
	template<typename T, typename... TParams>
	typename std::enable_if<sizeof(T) >= HalfPageSize && std::is_trivially_destructible<T>::value, T>::type*
	allocate(TParams&&... params)
	{
		char* address = allocateLarge(sizeof(T), alignof(T));
		return new (address) T(params...);
	}
	
	template<typename T>
	T* allocateDynamic(size_t count = 1, size_t alignment = alignof(T))
	{
		size_t totalSize;
		if (__builtin_umull_overflow(count, sizeof(T), &totalSize))
		{
			assert(false);
			return nullptr;
		}
		
		if (totalSize < HalfPageSize)
		{
			return new (allocateSmall(totalSize, alignment)) T[count];
		}
		return new (allocateLarge(totalSize, alignment)) T[count];
	}
	
	char* copyString(const char* begin, const char* end)
	{
		if (end >= begin)
		{
			size_t size = size_t(end - begin);
			if (auto memory = allocateDynamic<char>(size + 1))
			{
				std::copy(begin, end, memory);
				memory[size] = 0;
				return memory;
			}
		}
		return nullptr;
	}
	
	char* copyString(llvm::StringRef string)
	{
		return copyString(string.begin(), string.end());
	}
};

#endif /* fcd__dumb_allocator_h */
