//
// pass_typerec.cpp
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

#include "dumb_allocator.h"
#include "not_null.h"
#include "metadata.h"
#include "pass_typerec.h"

#include <llvm/ADT/PostOrderIterator.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include <deque>
#include <unordered_map>

// The type recovery pass recovers the layout of structures and class hierarchies from an execution stream based on how
// pointers are used. (It also recovers the stack frames of functions, since the stack can easily be treated as a
// pointer to a structure.) It uses two major sources of information.
//
// ## Type Sinks
//
// Type sinks are place in the code where we know for sure what the type of a value is. Our best source is function
// calls to functions that we know about. Our second-best source is when a value is loaded, **transformed** (operated on
// by IR instructions like add, sub, mul, etc) and stored again, and when a value is loaded and interpreted as a
// pointer.
//
// We discard operations that merely load something and store it somewhere else because compilers are starting to
// seriously not care about the type of things that are just moved around. For instance, the Swift compiler will use SSE
// and AVX instructions to do large loads and large stores from one structure to the next, over a whole range of fields.
// These operations must not count as type sinks, and this is why fcd uses the additional "transformed" criteria.
//
// ## The Dominator Tree
//
// Fcd combines the information obtained with type sinks with the dominator tree. This is because, especially in C++,
// functions can accept pointers to base types and do a type switch within the function. Fcd and LLVM do this a lot, and
// languages that support discriminated unions also do. The idea is that if you have a class hierarchy that has a base
// class B and derived classes D1 and D2, if you test the type of your B* and find out that it is a D1*, and branch
// accordingly, the code following that branch is probably aware of that fact, and may directly access fields (or call
// functions that access fields) in ways that are incompatible with the layout of class D2. Logically, the developer
// (and the compiler) know that the pointer is a pointer to a D1 only in blocks that are dominated by the type check.
//
// Note that fcd doesn't try to determine what a "type check" is: it merely looks at parallel branches in the dominator
// tree and doesn't try too hard to unify types in different branches when they don't match. After all, a type check
// could be checking a field, checking another function parameter, or calling a special function, and we want this
// algorithm to work either way.

using namespace std;
using namespace llvm;

namespace
{
	struct ObjectAddress;
	typedef SmallPtrSet<ObjectAddress*, 4> AddressGroup;
	
	struct ObjectAddress
	{
		enum Type
		{
			Direct,
			Fork,
			ConstantOffset,
			VariableOffset,
		};
		
		Type type;
		
		ObjectAddress(Type type)
		: type(type)
		{
		}
	};
	
	// Object address represented by a LLVM value that is not the product of any instruction (for instance, function
	// parameters). The Value associated with each object is stored in a side table, so this structure is empty.
	struct DirectObjectAddress : public ObjectAddress
	{
		DirectObjectAddress()
		: ObjectAddress(ObjectAddress::Direct)
		{
		}
		
		static bool classof(const ObjectAddress* address)
		{
			return address->type == Direct;
		}
	};
	
	struct RelativeObjectAddress : public ObjectAddress
	{
		NOT_NULL(ObjectAddress) base;
		
		RelativeObjectAddress(ObjectAddress::Type type, NOT_NULL(ObjectAddress) base)
		: ObjectAddress(type), base(base)
		{
		}
		
		static bool classof(const ObjectAddress* address)
		{
			return address->type != Direct;
		}
	};
	
	template<ObjectAddress::Type BaseType>
	struct ObjectAddressBase : public RelativeObjectAddress
	{
		ObjectAddressBase(NOT_NULL(ObjectAddress) base)
		: RelativeObjectAddress(BaseType, base)
		{
		}
		
		static bool classof(const ObjectAddress* address)
		{
			return address->type == BaseType;
		}
	};
	
	// A "fork" is an object address that is the same as another one in the program. This indirection blocks address
	// groups from propagating across unrelated dominator tree branches. This one is not specifically associated to any
	// Value, since it is only virtually different from the base address.
	struct ForkObjectAddress : public ObjectAddressBase<ObjectAddress::Fork>
	{
		ForkObjectAddress(NOT_NULL(ObjectAddress) base)
		: ObjectAddressBase<ObjectAddress::Fork>(base)
		{
		}
	};
	
	// Object address represented by an addition or subtraction to another object address object.
	struct ConstantOffsetObjectAddress : public ObjectAddressBase<ObjectAddress::Direct>
	{
		int64_t offset;
		
		ConstantOffsetObjectAddress(NOT_NULL(ObjectAddress) base, int64_t offset)
		: ObjectAddressBase<ObjectAddress::Direct>(base), offset(offset)
		{
		}
	};
	
	// Object address represented by a variable offset into another object address. This is generally an array index.
	// While the index is allowed to be variable, the stride is not. If the stride is variable, there's not much to
	// find out.
	struct VariableOffsetObjectAddress : public ObjectAddressBase<ObjectAddress::ConstantOffset>
	{
		NOT_NULL(Value) index;
		int64_t stride;
		
		VariableOffsetObjectAddress(NOT_NULL(ObjectAddress) base, NOT_NULL(Value) index, int64_t stride)
		: ObjectAddressBase<ObjectAddress::ConstantOffset>(base), index(index), stride(stride)
		{
		}
	};
	
	struct ObjectAddressInfo
	{
		Value* value;
		Type* type;
		ObjectAddress* address;
		AddressGroup* addressGroup;
	};
	
	struct RecoveryContext
	{
		Module& module;
		DumbAllocator pool;
		unordered_set<Function*> analyzedFunctions;
		
		// addresses that should all share the same recovered type
		deque<AddressGroup> addressGroups;
		unordered_map<Value*, ObjectAddress*> addresses;
		unordered_map<ObjectAddress*, ObjectAddressInfo> addressInfo;
		unordered_map<Function*, ObjectAddress*> returnValues;
		
		RecoveryContext(Module& module)
		: module(module)
		{
		}
		
		Value* getReturnValue(Function& fn)
		{
			if (!md::isPrototype(fn))
			{
			}
			return nullptr;
		}
		
		ObjectAddress& prepareObjectAddress(ObjectAddress& address, Value* value)
		{
			auto rootInsertResult = addresses.insert({value, &address});
			assert(rootInsertResult.second); (void) rootInsertResult;
			
			addressGroups.emplace_back();
			addressGroups.back().insert(&address);
			
			auto& info = addressInfo[&address];
			info.value = value;
			info.address = &address;
			info.addressGroup = &addressGroups.back();
			// This leaves "type" unset.
			
			return address;
		}
		
		ObjectAddress& addressByAdding(Value& base, Value& left, ConstantInt& right, bool addition)
		{
			ObjectAddress& baseAddress = addressForPointerValue(left);
			int64_t offset = static_cast<int64_t>(right.getLimitedValue());
			auto newObjectAddress = pool.allocate<ConstantOffsetObjectAddress>(&baseAddress, offset);
			return prepareObjectAddress(*newObjectAddress, &base);
		}
		
		ObjectAddress* addressByAdding(BinaryOperator& operation)
		{
			bool addition;
			if (operation.getOpcode() == Instruction::Add)
			{
				addition = true;
			}
			else if (operation.getOpcode() == Instruction::Sub)
			{
				addition = false;
			}
			else
			{
				return nullptr;
			}
			
			// Either side needs to be a constant. We can assume that at this point, constants have been folded and we won't
			// have something silly like constant+constant.
			
			// XXX: this should handle arrays, where one side is a value and the other is either a single variable (char
			// arrays) or a multiplication/shift. In the single variable case, it should figure out which side is the
			// pointer to the best of its ability (although either would be "technically" valid, probably).
			if (auto constantLeft = dyn_cast<ConstantInt>(operation.getOperand(0)))
			{
				return &addressByAdding(operation, *operation.getOperand(1), *constantLeft, addition);
			}
			else if (auto constantRight = dyn_cast<ConstantInt>(operation.getOperand(1)))
			{
				return &addressByAdding(operation, *operation.getOperand(0), *constantRight, addition);
			}
			return nullptr;
		}
		
		ObjectAddress& addressForPointerValue(Value& value)
		{
			auto addressIter = addresses.find(&value);
			if (addressIter != addresses.end())
			{
				return *addressIter->second;
			}
			
			if (auto castInst = dyn_cast<CastInst>(&value))
			{
				return addressForPointerValue(*castInst->getOperand(0));
			}
			
			if (auto binaryOp = dyn_cast<BinaryOperator>(&value))
				if (auto address = addressByAdding(*binaryOp))
				{
					return *address;
				}
			
			// Future work:
			// CallInst - it'd be great if we could walk back the return value.
			// ExtractValueInst - it'd be great if we could walk back to what was inserted in that field.
			
			// For anything else, create a new root.
			auto root = pool.allocate<DirectObjectAddress>();
			return prepareObjectAddress(*root, &value);
		}
	};
	
	struct FieldGroups
	{
		unordered_map<ObjectAddress*, DirectObjectAddress*> parents;
		unordered_map<DirectObjectAddress*, vector<ObjectAddress*>> members;
		
		DirectObjectAddress* findRoot(ObjectAddress* object)
		{
			if (auto root = dyn_cast<DirectObjectAddress>(object))
			{
				parents[root] = root;
				return root;
			}
			
			auto relativeObject = cast<RelativeObjectAddress>(object);
			auto root = findRoot(relativeObject->base);
			parents[object] = root;
			members[root].push_back(object);
			return root;
		}
		
		static int64_t getAddressOffset(ObjectAddress* address)
		{
			// IMPLEMENT ME
			return 0;
		}
		
		void build(RecoveryContext& context)
		{
			for (const auto& pair : context.addressInfo)
			{
				findRoot(pair.first);
			}
			
			for (auto& pair : members)
			{
				sort(pair.second.begin(), pair.second.end(), [](ObjectAddress* first, ObjectAddress* second)
				{
					return getAddressOffset(first) < getAddressOffset(second);
				});
			}
		}
	};
	
	void collectUsers(Instruction& instruction, unordered_set<Instruction*>& visited)
	{
		for (User* user : instruction.users())
		{
			if (auto inst = dyn_cast<Instruction>(user))
			if (visited.insert(inst).second && isa<PHINode>(inst))
			{
				collectUsers(*inst, visited);
			}
		}
	}
	
	Type& unifyTypeFromUses(LoadInst& load)
	{
		unordered_set<Instruction*> users;
		collectUsers(load, users);
		
		// TODO: do something smart with the users collection (look at TIE?)
		return *load.getType();
	}
	
	bool postDominates(PostDominatorTree& domTree, Instruction& a, Instruction& b)
	{
		auto aParent = a.getParent();
		auto bParent = b.getParent();
		if (aParent == bParent)
		{
			return all_of(a.getIterator(), aParent->end(), [&](Instruction& inst)
			{
				return &inst != &b;
			});
		}
		return domTree.dominates(aParent, bParent);
	}
}

char TypeRecovery::ID = 0;

void TypeRecovery::analyzeFunction(Function& fn)
{
	RecoveryContext context(*fn.getParent());
	
	if (!context.analyzedFunctions.insert(&fn).second || md::isPrototype(fn))
	{
		return;
	}
	
	// Walk every instruction to find loads and calls, as these can provide type sinks. The value of a load can be used
	// in different computations that allow us to determine what type of memory is used at the load's address. Even
	// better, calls downright impose a type on a pointer.
	//
	// We do not collect stores because compilers (and people) will frequently use the "wrong" store for the type of
	// data. For instance, the Swift compiler uses SSE instructions to move large chunks of data around memory, even
	// though that memory is likely not vector data. People have been caught using floating-point vector instructions to
	// move large chunks of data around, as well (and damned be denormalized values). Memset and memcpy employ various
	// tricks as well, and so do their inlined implementations.
	deque<CallInst*> calls;
	deque<LoadInst*> loads;
	
	// Basic blocks are visited in reverse post-order to minimize the chances of finding values that we don't know
	// about. (XXX: this could be dominator tree breadth-first, but LLVM doesn't have a breadth-first iterator
	// built-in.)
	for (BasicBlock* bb : ReversePostOrderTraversal<BasicBlock*>(&fn.getEntryBlock()))
	{
		for (Instruction& inst : *bb)
		{
			if (auto load = dyn_cast<LoadInst>(&inst))
			{
				loads.push_back(load);
			}
			else if (auto call = dyn_cast<CallInst>(&inst))
			{
				calls.push_back(call);
			}
		}
	}
	
	PostDominatorTree& postDomTree = getAnalysis<PostDominatorTreeWrapperPass>(fn).getPostDomTree();
	for (auto load : loads)
	{
		ObjectAddress& address = context.addressForPointerValue(*load->getPointerOperand());
		context.addressInfo[&address].type = &unifyTypeFromUses(*load);
		
		// Walk back to "source" of address, creating object addresses as needed for forks.
		if (auto currentAddress = dyn_cast<RelativeObjectAddress>(&address))
		{
			while (auto parentAddress = dyn_cast<RelativeObjectAddress>(currentAddress))
			{
				if (auto value = context.addressInfo[parentAddress].value)
				{
					if (auto inst = dyn_cast<Instruction>(value))
					if (!postDominates(postDomTree, *inst, *load))
					{
						auto nakedFork = context.pool.allocate<ForkObjectAddress>(parentAddress);
						auto& fork = context.prepareObjectAddress(*nakedFork, nullptr);
						currentAddress->base = &fork;
						break;
					}
				}
				else
				{
					assert(isa<ForkObjectAddress>(parentAddress));
					break;
				}
				currentAddress = parentAddress;
			}
		}
	}
	
	// Build structure types. First, bundle together object addresses based on their base address.
	FieldGroups groups;
	groups.build(context);
	
	for (auto call : calls)
	{
		// run analysis on function, add type equivalence across procedure boundaries
	}
}

TypeRecovery::TypeRecovery()
: llvm::ModulePass(ID)
{
}

TypeRecovery::~TypeRecovery()
{
}

void TypeRecovery::getAnalysisUsage(AnalysisUsage& au) const
{
	au.addRequired<DominatorTreeWrapperPass>();
	au.addPreserved<DominatorTreeWrapperPass>();
	au.addRequired<PostDominatorTreeWrapperPass>();
	au.addPreserved<PostDominatorTreeWrapperPass>();
}

bool TypeRecovery::runOnModule(Module& module)
{
	bool changed = false;
	for (Function& function : module)
	{
		analyzeFunction(function);
	}
	return changed;
}
