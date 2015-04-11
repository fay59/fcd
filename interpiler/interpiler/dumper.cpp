//
//  dumper.cpp
//  interpiler
//
//  Created by Félix on 2015-04-11.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include "dumper.h"

using namespace std;

dumped_item::dumped_item(const string& local)
: local_reference(local)
{
}

dumped_item::dumped_item(const string& local, const string& global_decl, const string& global_def)
: global_declaration(global_decl), global_definition(global_def)
{
}

dumper::dumper(const string& ctxname)
: llvm_context_name(ctxname)
{
}

dumped_item& dumper::emplace(intptr_t key, const string &local)
{
	return dumps.emplace(make_pair(key, dumped_item(local))).first->second;
}

dumped_item& dumper::emplace(intptr_t key, const string &local, const string &global_def, const string &global_decl)
{
	return dumps.emplace(make_pair(key, dumped_item(local, global_def, global_decl))).first->second;
}
