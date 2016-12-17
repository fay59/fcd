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
#include "passes.h"
#include "pointer_discovery.h"

#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include <deque>
#include <unordered_map>
#include <unordered_set>

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
	struct TypeMember
	{
		Type* type;
		ObjectAddress* address;
		
		int64_t startOffset() const
		{
			return address->getOffsetFromRoot();
		}
		
		int64_t endOffset(Module& module) const
		{
			return startOffset() + module.getDataLayout().getTypeStoreSize(type) / 8;
		}
	};
}

char TypeRecovery::ID = 0;

TypeRecovery::TypeRecovery()
: llvm::ModulePass(ID)
{
}

TypeRecovery::~TypeRecovery()
{
}

void TypeRecovery::getAnalysisUsage(AnalysisUsage& au) const
{
	au.addRequired<ExecutableWrapper>();
	au.addPreserved<ExecutableWrapper>();
	au.addRequired<DominatorTreeWrapperPass>();
	au.addPreserved<DominatorTreeWrapperPass>();
}

bool TypeRecovery::doInitialization(Module& module)
{
	auto i8T = Type::getInt8Ty(module.getContext());
	auto sizeT = Type::getIntNTy(module.getContext(), module.getDataLayout().getPointerSizeInBits());
	FunctionType* adjustPointerType = FunctionType::get(i8T, { i8T, sizeT }, false);
	adjustPointer = module.getOrInsertFunction("fcd.adjust.ptr", adjustPointerType);
	return true;
}

bool TypeRecovery::runOnModule(Module& module)
{
	bool changed = false;
	
	pointers.reset(new PointerDiscovery);
	pointers->analyzeModule(*getAnalysis<ExecutableWrapper>().getExecutable(), module);
	
	for (Function& fn : module)
	{
		// Split objects in function by root.
		unordered_map<RootObjectAddress*, deque<ObjectAddress*>> addresses;
		if (auto addressesInFunction = pointers->getAddressesInFunction(fn))
		{
			for (ObjectAddress* pointer : *addressesInFunction)
			{
				addresses[&pointer->getRoot()].push_back(pointer);
			}
		}
		
		errs() << fn.getName() << '\n';
		for (auto& pair : addresses)
		{
			sort(pair.second.begin(), pair.second.end(), [](ObjectAddress* a, ObjectAddress* b)
			{
				return a->getOffsetFromRoot() < b->getOffsetFromRoot();
			});
			
			for (ObjectAddress* address : pair.second)
			{
				errs() << '\t';
				address->dump();
				if (address->unification->size() > 1)
				{
					errs() << "\t\tsame as ";
					for (ObjectAddress* same : *address->unification)
					{
						same->print(errs());
						errs() << ", ";
					}
					errs() << '\n';
				}
			}
			errs() << '\n';
		}
	}
	
	return changed;
}

RegisterPass<TypeRecovery> typeRecovery("typerecovery", "Recover structure behind pointers");

ModulePass* createTypeRecoveryPass()
{
	return new TypeRecovery;
}
