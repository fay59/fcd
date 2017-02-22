//
// translation_maps.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef translation_maps_h
#define translation_maps_h


#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>

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
	std::unordered_map<uint64_t, llvm::BasicBlock*> blocks;
	std::map<uint64_t, llvm::BasicBlock*> stubs;
	
public:
	AddressToBlock(llvm::Function& fn)
	: insertInto(fn)
	{
	}
	
	bool getOneStub(uint64_t& address);
	
	llvm::BasicBlock* blockToInstruction(uint64_t address);
	llvm::BasicBlock* implementInstruction(uint64_t address);
};

#endif /* translation_maps_hpp */
