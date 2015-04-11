//
//  interpile.cpp
//  interpiler
//
//  Created by Félix on 2015-04-09.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include <memory>

#include "type_dumper.h"

using namespace llvm;
using namespace std;

void interpile(LLVMContext& context, unique_ptr<Module> module, ostream& header, ostream& impl);

void interpile(LLVMContext& context, unique_ptr<Module> module, const string& class_name, ostream& header, ostream& impl)
{
	type_dumper types("context");
	for (const GlobalVariable& var : module->getGlobalList())
	{
		types.dump(var.getType());
	}
	
	for (const Function& func : module->getFunctionList())
	{
		types.dump(func.getType());
	}
	
	for (const auto& pair : types)
	{
		const string& decl = pair.second.global_declaration;
		if (decl.length() > 0)
		{
			cout << decl << endl;
		}
	}
	
	cout << endl;
	for (const auto& pair : types)
	{
		const string& def = pair.second.global_definition;
		if (def.length() > 0)
		{
			cout << def << endl;
		}
	}
	
	cout << endl << '{' << endl;
	for (const auto& pair : types)
	{
		const string& local = pair.second.local_reference;
		if (local.length() > 0)
		{
			cout << '\t' << local << ";" << endl;
		}
	}
	cout << '}' << endl;
}
