//
// translation_maps.cpp
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

#include "metadata.h"
#include "translation_maps.h"

using namespace llvm;
using namespace std;

Function* AddressToFunction::insertFunction(uint64_t address)
{
	char defaultName[] = "func_0000000000000000";
	snprintf(defaultName, sizeof defaultName, "func_%" PRIx64, address);
	
	// XXX: do we really want external linkage? this has an impact on possible optimizations
	Function* fn = Function::Create(&fnType, GlobalValue::ExternalLinkage, defaultName, &module);
	md::setVirtualAddress(*fn, address);
	md::setIsPartOfOutput(*fn);
	md::setArgumentsRecoverable(*fn);
	return fn;
}

size_t AddressToFunction::getDiscoveredEntryPoints(unordered_set<uint64_t> &entryPoints) const
{
	size_t total = 0;
	for (const auto& pair : functions)
	{
		if (md::isPrototype(*pair.second))
		{
			entryPoints.insert(pair.first);
			++total;
		}
	}
	return total;
}

Function* AddressToFunction::getCallTarget(uint64_t address)
{
	Function*& result = functions[address];
	
	if (result == nullptr)
	{
		result = insertFunction(address);
	}
	return result;
}

Function* AddressToFunction::createFunction(uint64_t address)
{
	Function*& result = functions[address];
	if (result == nullptr)
	{
		result = insertFunction(address);
	}
	else if (!md::isPrototype(*result))
	{
		// the function needs to be fresh and new
		return nullptr;
	}
	
	// reset prototype status (and everything else, really)
	result->deleteBody();
	BasicBlock::Create(result->getContext(), "entry", result);
	md::setIsPartOfOutput(*result);
	md::setVirtualAddress(*result, address);
	md::setArgumentsRecoverable(*result);
	return result;
}

bool AddressToBlock::getOneStub(uint64_t& address) const
{
	auto iter = stubs.begin();
	if (iter != stubs.end())
	{
		address = iter->first;
		return true;
	}
	return false;
}

llvm::BasicBlock* AddressToBlock::blockToInstruction(uint64_t address)
{
	auto iter = blocks.find(address);
	if (iter != blocks.end())
	{
		return iter->second;
	}
	
	BasicBlock*& stub = stubs[address];
	if (stub == nullptr)
	{
		stub = BasicBlock::Create(insertInto.getContext(), "", &insertInto);
		ReturnInst::Create(insertInto.getContext(), stub);
	}
	return stub;
}

llvm::BasicBlock* AddressToBlock::implementInstruction(uint64_t address)
{
	BasicBlock*& bodyBlock = blocks[address];
	if (bodyBlock != nullptr)
	{
		return nullptr;
	}
	
	bodyBlock = BasicBlock::Create(insertInto.getContext(), "", &insertInto);
	
	unsigned pointerSize = ((sizeof address * CHAR_BIT) - __builtin_clzll(address) + CHAR_BIT - 1) / CHAR_BIT * 2;
	
	// set block name (aesthetic reasons)
	char blockName[] = "0000000000000000";
	snprintf(blockName, sizeof blockName, "%0.*" PRIx64, pointerSize, address);
	bodyBlock->setName(blockName);
	
	auto iter = stubs.find(address);
	if (iter != stubs.end())
	{
		iter->second->replaceAllUsesWith(bodyBlock);
		iter->second->eraseFromParent();
		stubs.erase(iter);
	}
	return bodyBlock;
}
