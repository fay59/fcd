//
// result_function.cpp
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

#include "llvm_warnings.h"
#include "metadata.h"
#include "result_function.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/InstVisitor.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

result_function::result_function(Function& function, uint64_t virtualAddress)
: function(&function)
{
	assert(function.isDeclaration() || md::isPrototype(function));
	
	// also deletes metadata...
	function.deleteBody();
	// ... so this needs to be added back
	md::setVirtualAddress(function, virtualAddress);
}

result_function::result_function(result_function&& that)
{
	blocks = move(that.blocks);
	stubs = move(that.stubs);
	intrins = move(that.intrins);
	callees = move(that.callees);
	function = that.function;
	that.function = nullptr;
}

result_function::~result_function()
{
	if (auto fn = function)
	{
		fn->removeFromParent();
	}
}

BasicBlock* result_function::get_implemented_block(uint64_t address)
{
	auto iter = blocks.find(address);
	if (iter == blocks.end())
	{
		return nullptr;
	}
	return iter->second;
}

BasicBlock& result_function::get_destination(uint64_t address)
{
	auto iter = blocks.find(address);
	if (iter == blocks.end())
	{
		iter = stubs.find(address);
		if (iter == stubs.end())
		{
			BasicBlock* stub = BasicBlock::Create(function->getContext(), "", function);
			new UnreachableInst(function->getContext(), stub);
			iter = stubs.insert(make_pair(address, stub)).first;
		}
	}
	return *iter->second;
}

void result_function::eat(Function* func, uint64_t address)
{
	assert(blocks.find(address) == blocks.end());
	BasicBlock* entry = &func->getEntryBlock();
	//entry->setName(func->getName());
	blocks.insert(make_pair(address, entry));
	
	// Copy to vector to avoid iterating the BB list while modifying it.
	vector<BasicBlock*> blocksInFunction;
	for (BasicBlock& bb : func->getBasicBlockList())
	{
		blocksInFunction.push_back(&bb);
	}
	
	for (BasicBlock* bb : blocksInFunction)
	{
		assert(bb->getTerminator());
		bb->removeFromParent();
		bb->insertInto(function);
		
		for (auto iter = bb->begin(); iter != bb->end(); iter++)
		{
			if (CallInst* call = dyn_cast<CallInst>(iter))
			{
				if (call->getCalledFunction() != nullptr)
				{
					bb = bb->splitBasicBlock(iter);
					iter = bb->begin();
					intrins.push_back(bb);
				}
			}
		}
	}
	
	for (auto iter1 = func->arg_begin(), iter2 = function->arg_begin(); iter1 != func->arg_end(); iter1++, iter2++)
	{
		iter1->replaceAllUsesWith(iter2);
	}
	
	auto stubIter = stubs.find(address);
	if (stubIter != stubs.end())
	{
		BasicBlock* stub = stubIter->second;
		stub->replaceAllUsesWith(entry);
		stub->eraseFromParent();
	}
	
	func->eraseFromParent();
}

Function* result_function::take()
{
	auto f = function;
	function = nullptr;
	return f;
}

result_function::intrin_iterator result_function::substitue(intrin_iterator intrin, llvm::BasicBlock *bb)
{
	BasicBlock* intrinBlock = *intrin;
	if (bb != nullptr)
	{
		bb->insertInto(function);
		intrinBlock->replaceAllUsesWith(bb);
		intrinBlock->eraseFromParent();
	}
	return intrins.erase(intrin);
}
