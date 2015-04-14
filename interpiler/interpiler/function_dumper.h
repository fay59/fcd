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

class function_dumper
{
	std::string prototypes_body;
	mutable llvm::raw_string_ostream body;
	std::unordered_set<llvm::Function*> known_functions;
	llvm::LLVMContext& context;
	type_dumper& types;
	global_dumper& globals;
	
	std::string make_function(llvm::Function* function, const std::string& prototype);
	
public:
	function_dumper(llvm::LLVMContext& context, type_dumper& types, global_dumper& globals);
	
	std::unique_ptr<std::string> accumulate(llvm::Function* function);
	std::string get_prototypes() const;
};

#endif /* defined(__interpiler__function_dumper__) */
