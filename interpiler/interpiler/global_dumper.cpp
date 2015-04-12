//
//  global_dumper.cpp
//  interpiler
//
//  Created by Félix on 2015-04-11.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include "dump_constant.h"
#include "global_dumper.h"

using namespace std;
using namespace llvm;

#define ENUM_STRING(x) [(size_t)x] = #x

namespace
{
	constexpr char nl = '\n';
	
	template<typename T, size_t N>
	[[gnu::always_inline]]
	constexpr size_t countof(const T (&)[N]) { return N; }
	
	string threadLocalModes[] = {
		ENUM_STRING(GlobalValue::NotThreadLocal),
		ENUM_STRING(GlobalValue::GeneralDynamicTLSModel),
		ENUM_STRING(GlobalValue::LocalDynamicTLSModel),
		ENUM_STRING(GlobalValue::InitialExecTLSModel),
		ENUM_STRING(GlobalValue::LocalExecTLSModel),
	};
	
	string linkageTypes[] = {
		ENUM_STRING(GlobalValue::ExternalLinkage),
		ENUM_STRING(GlobalValue::AvailableExternallyLinkage),
		ENUM_STRING(GlobalValue::LinkOnceAnyLinkage),
		ENUM_STRING(GlobalValue::LinkOnceODRLinkage),
		ENUM_STRING(GlobalValue::WeakAnyLinkage),
		ENUM_STRING(GlobalValue::WeakODRLinkage),
		ENUM_STRING(GlobalValue::AppendingLinkage),
		ENUM_STRING(GlobalValue::InternalLinkage),
		ENUM_STRING(GlobalValue::PrivateLinkage),
		ENUM_STRING(GlobalValue::ExternalWeakLinkage),
		ENUM_STRING(GlobalValue::CommonLinkage),
	};
}

llvm::raw_ostream& global_dumper::on_index(size_t index)
{
	return function_body << '\t' << "vars[" << index << "]";
}

llvm::raw_ostream& global_dumper::insert(GlobalVariable* var)
{
	size_t index = var_indices.size();
	var_indices[var] = index;
	return on_index(index) << " = ";
}

void global_dumper::make_global(GlobalVariable *var)
{
	assert((size_t)var->getThreadLocalMode() < countof(threadLocalModes));
	assert((size_t)var->getLinkage() < countof(linkageTypes));
	
	size_t typeIndex = types.accumulate(var->getType()->getPointerElementType());
	size_t varIndex = var_indices.size();
	
	string initializer = "nullptr";
	if (var->hasInitializer())
	{
		string prefix;
		raw_string_ostream ss(prefix);
		ss << "var" << varIndex << "_";
		initializer = dump_constant(function_body, prefix, var->getInitializer());
	}
	
	insert(var) << "new llvm::GlobalVariable("
		<< "module, " // Module&
		<< "types[" << typeIndex << "], " // Type*
		<< var->isConstant() << ", " // bool isConstant
		<< initializer << ", "; // Constant* initializer
	function_body << '"';
	function_body.write_escaped(var->getName()); // const Twine& name
	function_body << "\", ";
	function_body << "nullptr, " // GlobalVariable* insertBefore
		<< threadLocalModes[(size_t)var->getThreadLocalMode()] << ", " // TLMode
		<< var->getType()->getAddressSpace() << ", " // addressSpace
		<< var->isExternallyInitialized()
		<< ");" << nl;
	
	on_index(varIndex) << "->setLinkage(" << linkageTypes[(size_t)var->getLinkage()] << ");" << nl;
	
	if (var->isConstant())
	{
		on_index(varIndex) << "->setConstant(true);" << nl;
	}
	
	if (var->hasUnnamedAddr())
	{
		on_index(varIndex) << "->setUnnamedAddr(true);" << nl;
	}
	function_body << nl;
}

global_dumper::global_dumper(type_dumper& types)
: types(types), function_body(body)
{
}

size_t global_dumper::accumulate(GlobalVariable *variable)
{
	auto iter = var_indices.find(variable);
	if (iter == var_indices.end())
	{
		make_global(variable);
		return var_indices[variable];
	}
	return iter->second;
}

string global_dumper::get_function_body(const string &functionName) const
{
	function_body.flush();
	
	string result;
	raw_string_ostream ss(result);
	ss << "void " << functionName << "()" << nl;
	ss << '{' << nl;
	ss << '\t' << "globals.resize(" << var_indices.size() << ");" << nl;
	ss << body;
	ss << '}' << nl;
	ss.flush();
	return result;
}
