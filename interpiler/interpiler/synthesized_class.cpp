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

namespace
{
	constexpr char nl = '\n';
	
	std::string accessModifiers[] = {
		[synthesized_class::am_private] = "private",
		[synthesized_class::am_protected] = "protected",
		[synthesized_class::am_public] = "public",
	};
	
	template<typename T, size_t N>
	constexpr size_t countof(const T (&)[N])
	{
		return N;
	}
}

synthesized_class::synthesized_class(const string& name)
: name(name), constructor("", name)
{
}

void synthesized_class::print_declaration(raw_ostream &os) const
{
	access_modifier lastAccessModifier = am_private;
	os << "class " << name << nl;
	os << '{' << nl;
	for (const field& field : fields)
	{
		if (field.access != lastAccessModifier)
		{
			assert(field.access < countof(accessModifiers));
			os << nl << accessModifiers[field.access] << ':' << nl;
			lastAccessModifier = field.access;
		}
		os << '\t' << field.type << ' ' << field.name << ';' << nl;
	}
	os << nl;
	
	os << "public:" << nl;
	os << '\t' << name << "(llvm::LLVMContext& context, llvm::Module& module);" << nl;
	lastAccessModifier = am_public;
	
	for (const auto& pair : methods)
	{
		if (pair.first != lastAccessModifier)
		{
			assert(pair.first < countof(accessModifiers));
			os << nl << accessModifiers[pair.first] << ':' << nl;
			lastAccessModifier = pair.first;
		}
		os << '\t';
		pair.second.print_declaration(os);
		os << '\n';
	}
	os << "};" << nl;
}

void synthesized_class::print_definition(raw_ostream &os) const
{
	// constructor first
	os << name << "::" << name << "(";
	auto begin = constructor.params_begin();
	for (auto iter = constructor.params_begin(); iter != constructor.params_end(); iter++)
	{
		if (iter != begin)
		{
			os << ", ";
		}
		os << *iter;
	}
	os << ")" << nl;
	if (initializers.size() > 0)
	{
		os << '\t' << ": ";
		for (size_t i = 0; i < initializers.size(); i++)
		{
			if (i != 0)
			{
				os << ", ";
			}
			os << initializers[i];
		}
		os << '\n';
	}
	os << '{' << nl;
	for (auto iter = constructor.lines_begin(); iter != constructor.lines_end(); iter++)
	{
		os << '\t' << *iter << nl;
	}
	os << '}' << nl;
	os << nl;
	
	// and then methods
	for (const auto& pair : methods)
	{
		pair.second.print_definition(os, name);
		os << nl;
	}
}
