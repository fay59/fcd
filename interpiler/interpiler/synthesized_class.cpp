//
//  synthesized_class.cpp
//  interpiler
//
//  Created by Félix on 2015-04-15.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include "synthesized_class.h"

using namespace llvm;
using namespace std;

constexpr char nl = '\n';

synthesized_class::synthesized_class(const string& name)
: name(name), constructor("", name)
{
}

void synthesized_class::print_declaration(raw_ostream &os) const
{
	os << "class " << name << nl;
	os << '{' << nl;
	for (const string& field : fields)
	{
		os << '\t' << field << ';' << nl;
	}
	os << nl;
	
	os << "public:" << nl;
	os << '\t' << name << "(llvm::LLVMContext& context, llvm::Module& module);" << nl;
	os << nl;
	for (const synthesized_method& method : methods)
	{
		os << '\t';
		method.print_declaration(os);
		os << '\n';
	}
	os << "};" << nl;
}

void synthesized_class::print_definition(raw_ostream &os) const
{
	// constructor first
	os << name << "::" << name << "(llvm::LLVMContext& context, llvm::Module& module)" << nl;
	os << '\t' << ": context(context), module(module)" << nl;
	os << '{' << nl;
	for (auto iter = constructor.lines_begin(); iter != constructor.lines_end(); iter++)
	{
		os << '\t' << *iter << nl;
	}
	os << '}' << nl;
	os << nl;
	
	// and then methods
	for (const synthesized_method& method : methods)
	{
		method.print_definition(os, name);
		os << nl;
	}
}
