//
//  result_function.cpp
//  x86Emulator
//
//  Created by Félix on 2015-04-20.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/InstVisitor.h>
SILENCE_LLVM_WARNINGS_END()

#include "result_function.h"

using namespace llvm;
using namespace std;

result_function::result_function(Module& module, llvm::FunctionType& type, const string& name)
{
	function = cast<Function>(module.getOrInsertFunction(name, &type));
	assert(function->isDeclaration());
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
	entry->setName(func->getName());
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
