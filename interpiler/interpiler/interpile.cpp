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
#include <iostream>

using namespace llvm;
using namespace std;

void interpile(LLVMContext& context, unique_ptr<Module> module, ostream& header, ostream& impl);

class interpiler
{
	LLVMContext& context;
	unique_ptr<Module> module;
	ostream& header;
	ostream& impl;
	
public:
	interpiler(LLVMContext& context, unique_ptr<Module> module, ostream& header, ostream& impl)
	: context(context), module(move(module)), header(header), impl(impl)
	{
	}
};

void interpile(LLVMContext& context, unique_ptr<Module> module, ostream& header, ostream& impl)
{
	interpiler obj(context, move(module), header, impl);
}