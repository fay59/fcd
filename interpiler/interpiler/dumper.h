//
//  dumper.h
//  interpiler
//
//  Created by Félix on 2015-04-11.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __interpiler__dumper__
#define __interpiler__dumper__

#include <cstdint>
#include <string>
#include <iostream>
#include <unordered_map>

struct dumped_item
{
	std::string global_declaration;
	std::string global_definition;
	std::string local_reference;
	
	dumped_item() = default;
	dumped_item(const std::string& local);
	dumped_item(const std::string& local, const std::string& global_decl, const std::string& global_def);
};

class dumper
{
public:
	typedef std::unordered_map<intptr_t, dumped_item> collection_type;
	
protected:
	collection_type dumps;
	std::string llvm_context_name;
	
	dumped_item& emplace(intptr_t key, const std::string& local);
	dumped_item& emplace(intptr_t key, const std::string& local, const std::string& global_def, const std::string& global_decl);
	
public:
	explicit dumper(const std::string& ctxname);
	
	inline collection_type::iterator begin()
	{
		return dumps.begin();
	}
	
	inline collection_type::iterator end()
	{
		return dumps.end();
	}
};

#endif /* defined(__interpiler__dumper__) */
