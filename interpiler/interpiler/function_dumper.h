//
//  function_dumper.h
//  interpiler
//
//  Created by Félix on 2015-04-13.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __interpiler__function_dumper__
#define __interpiler__function_dumper__

#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
#include <memory>
#include <string>
#include <unordered_set>

#include "global_dumper.h"
#include "type_dumper.h"
#include "synthesized_class.h"

class function_dumper
{
	type_dumper& types;
	global_dumper& globals;
	synthesized_class& klass;
	std::unordered_set<llvm::Function*> known_functions;
	
	llvm::LLVMContext& context;
	
	void make_function(llvm::Function* function, synthesized_method& output);
	
public:
	function_dumper(llvm::LLVMContext& context, synthesized_class& klass, type_dumper& types, global_dumper& globals);
	
	void accumulate(llvm::Function* function);
};

#endif /* defined(__interpiler__function_dumper__) */
