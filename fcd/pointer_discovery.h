//
// pass_pointerdiscovery.h
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

#ifndef pass_pointerdiscovery_h
#define pass_pointerdiscovery_h

#include "dumb_allocator.h"
#include "executable.h"
#include "not_null.h"

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/raw_ostream.h>

#include <deque>
#include <unordered_map>
#include <unordered_set>

struct ObjectAddress;
struct RootObjectAddress;
typedef NOT_NULL(std::unordered_set<ObjectAddress*>) UnificationSet;

struct ObjectAddress
{
	enum Type
	{
		Root,
		ConstantOffset,
		VariableOffset,
		ConfusedVariableOffset, // never publicly returned
	};
	
	NOT_NULL(llvm::Value) value;
	UnificationSet unification;
	Type type;
	
	ObjectAddress(Type type, NOT_NULL(llvm::Value) value, UnificationSet unification)
	: type(type), value(value), unification(unification)
	{
	}
	
	virtual RootObjectAddress& getRoot() = 0;
	virtual int64_t getOffsetFromRoot() const = 0;
	virtual void print(llvm::raw_ostream& os) const = 0;
	void dump() const;
};

struct RootObjectAddress : public ObjectAddress
{
	RootObjectAddress(NOT_NULL(llvm::Value) value, UnificationSet unification)
	: ObjectAddress(Root, value, unification)
	{
	}
	
	virtual RootObjectAddress& getRoot() override;
	virtual int64_t getOffsetFromRoot() const override;
	virtual void print(llvm::raw_ostream& os) const override;
};

struct PossibleRootObjectAddress;

struct RelativeObjectAddress : public ObjectAddress
{
	NOT_NULL(ObjectAddress) parent;
	
	RelativeObjectAddress(Type type, NOT_NULL(llvm::Value) value, UnificationSet unification, NOT_NULL(ObjectAddress) parent);
	
	virtual RootObjectAddress& getRoot() override final;
};

struct ConstantOffsetObjectAddress : public RelativeObjectAddress
{
	int64_t offset;
	
	ConstantOffsetObjectAddress(NOT_NULL(llvm::Value) value, UnificationSet unification, NOT_NULL(ObjectAddress) parent, int64_t offset)
	: RelativeObjectAddress(ConstantOffset, value, unification, parent), offset(offset)
	{
	}
	
	virtual int64_t getOffsetFromRoot() const override;
	virtual void print(llvm::raw_ostream& os) const override;
};

struct VariableOffsetObjectAddress : public RelativeObjectAddress
{
	NOT_NULL(llvm::Value) index;
	uint64_t stride;
	
	VariableOffsetObjectAddress(NOT_NULL(llvm::Value) value, UnificationSet unification, NOT_NULL(ObjectAddress) parent, NOT_NULL(llvm::Value) index, uint64_t stride)
	: RelativeObjectAddress(VariableOffset, value, unification, parent), index(index), stride(stride)
	{
	}
	
	virtual int64_t getOffsetFromRoot() const override;
	virtual void print(llvm::raw_ostream& os) const override;
};

// Find all the pointers in a module, identify which pointers should/may point to the same type of memory.
class PointerDiscovery
{
	friend class FunctionPointerDiscovery;
	
	DumbAllocator pool;
	Executable* executable;
	std::deque<PossibleRootObjectAddress*> possibleRoots;
	std::deque<std::unordered_set<ObjectAddress*>> unificationSets;
	std::unordered_map<llvm::Function*, std::deque<ObjectAddress*>> addressesInFunctions;
	std::unordered_map<llvm::Value*, RootObjectAddress*> roots;
	
	void analyzeFunction(llvm::Function& fn);
	
public:
	void analyzeModule(Executable& executable, llvm::Module& module);
	
	const std::deque<ObjectAddress*>& getAddressesInFunction(llvm::Function& fn) const
	{
		return addressesInFunctions.at(&fn);
	}
};

#endif /* pass_pointerdiscovery_hpp */
