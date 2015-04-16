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
#include <memory>
#include <unordered_map>
#include <string>

#include "synthesized_method.h"
#include "type_dumper.h"

class global_dumper
{
	type_dumper& types;
	synthesized_method& method;
	std::string& resizeLine;
	std::unordered_map<llvm::GlobalObject*, size_t> var_indices;
	
	std::unique_ptr<llvm::raw_ostream> ostream;
	llvm::raw_ostream& on_index(size_t index);
	llvm::raw_ostream& insert(llvm::GlobalObject* var);
	void make_global(llvm::GlobalVariable* var);
	void make_global(llvm::Function* fn);
	
public:
	explicit global_dumper(synthesized_class& klass, type_dumper& types);
	
	size_t accumulate(llvm::GlobalVariable* variable);
	size_t accumulate(llvm::Function* func);
};

#endif /* defined(__interpiler__global_dumper__) */
