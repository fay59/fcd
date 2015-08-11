//
// dumb_allocator.h
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

#ifndef dumb_allocator_cpp
#define dumb_allocator_cpp

#include <algorithm>
#include <cassert>
#include <iterator>
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

// PooledDeque needs to be a separate class because it is trivially destructible. It would be simpler if we could use
// deque<T, Allocator> instead, but we live in a sad world.

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
class PooledDequeIterator : public std::iterator<std::input_iterator_tag, T, void>
{
	PooledDequeBuffer<T>* buffer;
	size_t index;
	
public:
	PooledDequeIterator(PooledDequeBuffer<T>* buffer)
	: buffer(buffer), index(0)
	{
		if (this->buffer != nullptr && this->buffer->used == 0)
		{
			this->buffer = nullptr;
		}
	}
	
	inline T& operator*()
	{
		return buffer->pointer[index];
	}
	
	inline T* operator->()
	{
		return &operator*();
	}
	
	inline bool operator==(const PooledDequeIterator<T>& that) const
	{
		return buffer == that.buffer && index == that.index;
	}
	
	inline bool operator!=(const PooledDequeIterator<T>& that) const
	{
		return !(*this == that);
	}
	
	inline PooledDequeIterator<T>& operator++()
	{
		index++;
		// This can happen at most 2 times. If it happens a second time, it'll set the iterator to the end iterator
		// value.
		while (buffer != nullptr && index == buffer->used)
		{
			buffer = buffer->next;
			index = 0;
		}
		return *this;
	}
	
	inline PooledDequeIterator<T> operator++(int)
	{
		auto copy = *this;
		operator++();
		return copy;
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
	typedef PooledDequeIterator<T> iterator;
	typedef PooledDequeIterator<const T> const_iterator;
	
	PooledDeque(DumbAllocator& pool)
	: pool(pool)
	{
		first = &empty;
		last = first;
	}
	
	void push_back(const T& item)
	{
		if (size() != 0) assert(back() != item);
		newBufferIfNeeded();
		last->pointer[last->used] = item;
		last->used++;
	}
	
	template<typename TIter>
	void push_back(TIter begin, TIter end)
	{
		for (auto iter = begin; iter != end; ++iter)
		{
			push_back(*iter);
		}
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
		auto buffer = last;
		while (buffer->used == 0)
		{
			buffer = buffer->prev;
		}
		return buffer->pointer[buffer->used - 1];
	}
	
	T* back_or_null()
	{
		if (first->used > 0)
		{
			return &back();
		}
		return nullptr;
	}
	
	const_iterator cbegin() const
	{
		return const_iterator(reinterpret_cast<PooledDequeBuffer<const T>*>(first));
	}
	
	const_iterator cend() const
	{
		return const_iterator(nullptr);
	}
	
	iterator begin()
	{
		return iterator(first);
	}
	
	const_iterator begin() const
	{
		return cbegin();
	}
	
	iterator end()
	{
		return PooledDequeIterator<T>(nullptr);
	}
	
	const_iterator end() const
	{
		return cend();
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
