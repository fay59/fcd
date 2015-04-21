//
//  result_function.h
//  x86Emulator
//
//  Created by Félix on 2015-04-20.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __x86Emulator__result_function__
#define __x86Emulator__result_function__

#include <llvm/IR/Function.h>
#include <unordered_map>
#include <string>
#include <vector>

class result_function
{
	std::unordered_map<uint64_t, llvm::BasicBlock*> blocks;
	std::unordered_map<uint64_t, llvm::BasicBlock*> stubs;
	std::vector<llvm::BasicBlock*> intrins;
	llvm::Function* function;
	
public:
	typedef std::vector<llvm::BasicBlock*>::iterator intrin_iterator;
	
	result_function(llvm::Module& module, llvm::FunctionType& type, const std::string& name);
	result_function(result_function&& that);
	result_function(const result_function&) = delete;
	~result_function();
	
	inline llvm::Function* operator->() { return function; }
	
	llvm::BasicBlock* get_implemented_block(uint64_t address);
	llvm::BasicBlock& get_destination(uint64_t address);
	
	void eat(llvm::Function*, uint64_t address);
	
	llvm::Function* take();
	
	inline intrin_iterator intrin_begin() { return intrins.begin(); }
	inline intrin_iterator intrin_end() { return intrins.end(); }
	intrin_iterator substitue(intrin_iterator intrin, llvm::BasicBlock* bb = nullptr);
};

#endif /* defined(__x86Emulator__result_function__) */
