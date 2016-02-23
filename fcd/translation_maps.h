//
// translation_maps.h
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

#ifndef translation_maps_h
#define translation_maps_h

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
SILENCE_LLVM_WARNINGS_END()

#include <unordered_map>
#include <unordered_set>
#include <string>

class AddressToFunction
{
	llvm::Module& module;
	llvm::FunctionType& fnType;
	std::unordered_map<uint64_t, std::string> aliases;
	std::unordered_map<uint64_t, llvm::Function*> functions;
	
	llvm::Function* insertFunction(uint64_t address);
	
public:
	AddressToFunction(llvm::Module& module, llvm::FunctionType& fnType)
	: module(module), fnType(fnType)
	{
	}
	
	void clear()
	{
		aliases.clear();
		functions.clear();
	}
	
	size_t getDiscoveredEntryPoints(std::unordered_set<uint64_t>& entryPoints) const;
	
	llvm::Function* getCallTarget(uint64_t address);
	llvm::Function* createFunction(uint64_t address);
};

class AddressToBlock
{
	llvm::Function& insertInto;
	llvm::BasicBlock* returnBlock;
	std::unordered_map<uint64_t, llvm::BasicBlock*> blocks;
	std::unordered_map<uint64_t, llvm::BasicBlock*> stubs;
	
public:
	AddressToBlock(llvm::Function& fn)
	: insertInto(fn), returnBlock(nullptr)
	{
	}
	
	bool getOneStub(uint64_t& address) const;
	
	llvm::BasicBlock* blockToInstruction(uint64_t address);
	llvm::BasicBlock* implementInstruction(uint64_t address);
};

#endif /* translation_maps_hpp */
