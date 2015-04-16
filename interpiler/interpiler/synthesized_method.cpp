//
//  synthesized_method.cpp
//  interpiler
//
//  Created by Félix on 2015-04-15.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include "synthesized_method.h"

using namespace llvm;
using namespace std;

synthesized_method::synthesized_method(const string& returnType, const string& name)
: return_type(returnType), name(name)
{
}

void synthesized_method::print_declaration(llvm::raw_ostream &os) const
{
	os << return_type << ' ' << name << '(';
	for (size_t i = 0; i < parameters.size(); i++)
	{
		if (i != 0)
		{
			os << ", ";
		}
		const auto& param = parameters[i];
		os << param.type << ' ' << param.name;
		if (param.default_value.size() > 0)
		{
			os << " = " << param.default_value;
		}
	}
	os << ");";
}

void synthesized_method::print_definition(llvm::raw_ostream &os, const std::string& ns_prefix) const
{
	os << return_type << ' ';
	if (ns_prefix.size() > 0)
	{
		os << ns_prefix << "::";
	}
	os << name << '(';
	
	for (size_t i = 0; i < parameters.size(); i++)
	{
		if (i != 0)
		{
			os << ", ";
		}
		const auto& param = parameters[i];
		os << param.type << ' ' << param.name;
	}
	os << ')' << '\n';
	os << '{' << '\n';
	for (const auto& line : code)
	{
		os << '\t' << line << '\n';
	}
	os << '}' << '\n';
}
