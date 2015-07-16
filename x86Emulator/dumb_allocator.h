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
class DumbAllocator
{
	static constexpr size_t DefaultPageSize = 0x1000 - 0x20;
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

template<typename T>
struct PooledDequeBuffer
{
	PooledDequeBuffer<T>* prev;
	PooledDequeBuffer<T>* next;
	size_t count;
	size_t used;
	T* pointer;
	
	PooledDequeBuffer()
	: prev(nullptr), next(nullptr), count(0), used(0), pointer(nullptr)
	{
	}
	
	PooledDequeBuffer(DumbAllocator& pool, PooledDequeBuffer<T>* prev, size_t count)
	: prev(prev), next(nullptr), count(count), used(0)
	{
		if (prev != nullptr)
		{
			prev->next = this;
		}
		pointer = pool.allocateDynamic<T>(count);
	}
};

template<typename T>
class PooledDeque
{
	static_assert(std::is_trivially_destructible<T>::value, "type needs to be trivially destructible");
	
	static PooledDequeBuffer<T> empty;
	
	DumbAllocator& pool;
	PooledDequeBuffer<T>* first;
	PooledDequeBuffer<T>* last;
	
	void newBufferIfNeeded()
	{
		if (last->used == last->count)
		{
			size_t allocCount = last->count;
			allocCount += last->prev == nullptr ? 5 : last->prev->count;
			if (last == &empty)
			{
				last = pool.template allocate<PooledDequeBuffer<T>>(pool, nullptr, allocCount);
				first = last;
			}
			else
			{
				last = pool.template allocate<PooledDequeBuffer<T>>(pool, last, allocCount);
			}
		}
	}
	
	PooledDequeBuffer<T>* seek(size_t index, size_t& indexInBuffer)
	{
		return const_cast<PooledDequeBuffer<T>*>(static_cast<const PooledDeque<T>*>(this)->seek(index, indexInBuffer));
	}
	
	const PooledDequeBuffer<T>* seek(size_t index, size_t& indexInBuffer) const
	{
		auto buffer = first;
		while (index >= buffer->used)
		{
			index -= buffer->used;
			buffer = buffer->next;
		}
		indexInBuffer = index;
		return buffer;
	}
	
public:
	PooledDeque(DumbAllocator& pool)
	: pool(pool)
	{
		first = &empty;
		last = first;
	}
	
	void push_back(const T& item)
	{
		newBufferIfNeeded();
		last->pointer[last->used] = item;
		last->used++;
	}
	
	size_t size() const
	{
		size_t count = 0;
		auto buffer = first;
		while (buffer != nullptr)
		{
			count += buffer->used;
			buffer = buffer->next;
		}
		return count;
	}
	
	// This implementation potentially wastes some space in return for speed.
	void erase_at(size_t index)
	{
		size_t indexInBuffer;
		auto buffer = seek(index, indexInBuffer);
		
		buffer->used--;
		for (size_t i = indexInBuffer; i < buffer->used; i++)
		{
			buffer->pointer[i] = buffer->pointer[i + 1];
		}
	}
	
	T& front()
	{
		return first->pointer[0];
	}
	
	T& back()
	{
		return last->pointer[last->used - 1];
	}
	
	const T& operator[](size_t index) const
	{
		size_t indexInBuffer;
		auto buffer = seek(index, indexInBuffer);
		return buffer->pointer[indexInBuffer];
	}
	
	T& operator[](size_t index)
	{
		return const_cast<T&>(static_cast<const PooledDeque<T>*>(this)->operator[](index));
	}
};

template<typename T>
PooledDequeBuffer<T> PooledDeque<T>::empty = PooledDequeBuffer<T>();

#endif /* dumb_allocator_cpp */
