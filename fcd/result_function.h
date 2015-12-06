//
// result_function.h
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

#ifndef fcd__result_function_h
#define fcd__result_function_h

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Function.h>
SILENCE_LLVM_WARNINGS_END()

#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>

class result_function
{
	friend class translation_context;
	
	std::unordered_map<uint64_t, llvm::BasicBlock*> blocks;
	std::unordered_map<uint64_t, llvm::BasicBlock*> stubs;
	std::unordered_set<uint64_t> callees;
	std::vector<llvm::BasicBlock*> intrins;
	llvm::Function* function;
	
public:
	typedef std::vector<llvm::BasicBlock*>::iterator intrin_iterator;
	typedef std::unordered_set<uint64_t>::const_iterator callee_iterator;
	
	result_function(llvm::Function& function, uint64_t virtualAddress);
	result_function(result_function&& that);
	result_function(const result_function&) = delete;
	~result_function();
	
	inline llvm::Function* operator->() { return function; }
	
	llvm::BasicBlock* get_implemented_block(uint64_t address);
	llvm::BasicBlock& get_destination(uint64_t address);
	
	void eat(llvm::Function*, uint64_t address);
	
	inline llvm::Function* get() { return function; }
	llvm::Function* take();
	
	inline callee_iterator callees_begin() { return callees.begin(); }
	inline callee_iterator callees_end() { return callees.end(); }
	
	inline intrin_iterator intrin_begin() { return intrins.begin(); }
	inline intrin_iterator intrin_end() { return intrins.end(); }
	intrin_iterator substitue(intrin_iterator intrin, llvm::BasicBlock* bb = nullptr);
};

#endif /* defined(fcd__result_function_h) */
