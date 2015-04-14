//
//  interpile.cpp
//  interpiler
//
//  Created by Félix on 2015-04-09.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include <iostream>
#include <memory>

#include "global_dumper.h"
#include "type_dumper.h"
#include "function_dumper.h"

using namespace llvm;
using namespace std;

void interpile(LLVMContext& context, unique_ptr<Module> module, llvm::raw_ostream& header, llvm::raw_ostream& impl);

void interpile(LLVMContext& context, unique_ptr<Module> module, const string& class_name, llvm::raw_ostream& header, llvm::raw_ostream& impl)
{
	type_dumper types;
	global_dumper globals(types);
	function_dumper functions(context, types, globals);
	
	for (Function& func : module->getFunctionList())
	{
		if (auto body = functions.accumulate(&func))
		{
			cout << *body << endl;
		}
	}
	
	//cout << types.get_function_body("make_types");
	//cout << globals.get_function_body("make_globals");
}
