//
//  synthesized_method.h
//  interpiler
//
//  Created by Félix on 2015-04-15.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __interpiler__synthesized_method__
#define __interpiler__synthesized_method__

#include <deque>
#include <llvm/Support/raw_ostream.h>
#include <string>

class synthesized_method
{
public:
	typedef std::deque<std::string> string_vector;
	
private:
	std::string return_type;
	std::string name;
	string_vector parameters;
	string_vector code;
	
	inline std::string& new_of(string_vector& vec)
	{
		vec.emplace_back();
		return vec.back();
	}
	
public:
	synthesized_method(const std::string& returnType, const std::string& name);
	
	inline std::string& new_param()
	{
		return new_of(parameters);
	}
	
	inline string_vector::const_iterator lines_begin() const { return code.begin(); }
	inline string_vector::const_iterator lines_end() const { return code.end(); }
	inline std::string& nl()
	{
		return new_of(code);
	}
	
	void print_declaration(llvm::raw_ostream& os) const;
	void print_definition(llvm::raw_ostream& os, const std::string& ns_prefix = "") const;
};

#endif /* defined(__interpiler__synthesized_method__) */
