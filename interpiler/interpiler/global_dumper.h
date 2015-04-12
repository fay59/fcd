//
//  global_dumper.h
//  interpiler
//
//  Created by Félix on 2015-04-11.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __interpiler__global_dumper__
#define __interpiler__global_dumper__

#include <cstdint>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/Support/raw_ostream.h>
#include <unordered_map>
#include <string>

#include "type_dumper.h"

class global_dumper
{
	type_dumper& types;
	std::string body;
	mutable llvm::raw_string_ostream function_body;
	std::unordered_map<llvm::GlobalVariable*, size_t> var_indices;
	
	llvm::raw_ostream& on_index(size_t index);
	llvm::raw_ostream& insert(llvm::GlobalVariable* var);
	void make_global(llvm::GlobalVariable* var);
	
public:
	explicit global_dumper(type_dumper& types);
	
	size_t accumulate(llvm::GlobalVariable* variable);
	std::string get_function_body(const std::string& functionName) const;
};

#endif /* defined(__interpiler__global_dumper__) */
