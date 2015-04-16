//
//  synthesized_class.h
//  interpiler
//
//  Created by Félix on 2015-04-15.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __interpiler__synthesized_class__
#define __interpiler__synthesized_class__

#include <deque>
#include <llvm/Support/raw_ostream.h>
#include <map>
#include <string>

#include "synthesized_method.h"

class synthesized_class
{
public:
	enum access_modifier
	{
		am_private,
		am_protected,
		am_public,
	};
	
private:
	struct field
	{
		access_modifier access;
		std::string type;
		std::string name;
		std::string initializer;
	};
	
	std::string name;
	synthesized_method constructor;
	std::deque<field> fields;
	std::multimap<access_modifier, synthesized_method> methods;
	
public:
	explicit synthesized_class(const std::string& name);
	
	inline void new_field(access_modifier access, const std::string& type, const std::string& name)
	{
		fields.emplace_back();
		field& f = fields.back();
		f.access = access;
		f.type = type;
		f.name = name;
	}
	
	inline void new_field(access_modifier access, const std::string& type, const std::string& name, const std::string& initializer)
	{
		fields.emplace_back();
		field& f = fields.back();
		f.access = access;
		f.type = type;
		f.name = name;
		f.initializer = initializer;
	}
	
	inline synthesized_method& new_method(access_modifier access, const std::string& returnType, const std::string& name)
	{
		return methods.insert(std::make_pair(access, synthesized_method(returnType, name)))->second;
	}
	
	inline synthesized_method::arg& ctor_param()
	{
		return constructor.new_param();
	}
	
	inline void ctor_param(const std::string& type, const std::string& name, const std::string& default_value = "")
	{
		constructor.new_param(type, name, default_value);
	}

	inline std::string& ctor_nl()
	{
		return constructor.nl();
	}
	
	void print_declaration(llvm::raw_ostream& os) const;
	void print_definition(llvm::raw_ostream& os) const;
};

#endif /* defined(__interpiler__synthesized_class__) */
