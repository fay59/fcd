//
//  global_dumper.cpp
//  interpiler
//
//  Created by Félix on 2015-04-11.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <llvm/IR/Function.h>

#include "dump_constant.h"
#include "global_dumper.h"

using namespace std;
using namespace llvm;

#define ENUM_STRING(x) [(size_t)x] = "llvm::" #x

namespace
{
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
	ostream.reset(new raw_string_ostream(method.nl()));
	return *ostream << "globals[" << index << "]";
}

llvm::raw_ostream& global_dumper::insert(GlobalObject* var)
{
	size_t index = var_indices.size();
	var_indices[var] = index;
	
	resizeLine.clear();
	(raw_string_ostream(resizeLine) << "globals.resize(" << var_indices.size() << ");");
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
		(raw_string_ostream(prefix) << "var" << varIndex << '_');
		initializer = dump_constant(method, types, prefix, var->getInitializer());
	}
	
	auto& declarationLine = insert(var);
	declarationLine << "new llvm::GlobalVariable("
		<< "module, " // Module&
		<< "types[" << typeIndex << "], " // Type*
		<< var->isConstant() << ", " // bool isConstant
		<< initializer << ", "; // Constant* initializer
	declarationLine << '"';
	declarationLine.write_escaped(var->getName()); // const Twine& name
	declarationLine << "\", ";
	declarationLine << "nullptr, " // GlobalVariable* insertBefore
		<< threadLocalModes[(size_t)var->getThreadLocalMode()] << ", " // TLMode
		<< var->getType()->getAddressSpace() << ", " // addressSpace
		<< var->isExternallyInitialized()
		<< ");";
	
	on_index(varIndex) << "->setLinkage(" << linkageTypes[(size_t)var->getLinkage()] << ");";
	
	if (var->isConstant())
	{
		on_index(varIndex) << "->setConstant(true);";
	}
	
	if (var->hasUnnamedAddr())
	{
		on_index(varIndex) << "->setUnnamedAddr(true);";
	}
	method.nl();
}

void global_dumper::make_global(Function* fn)
{
	assert((size_t)fn->getThreadLocalMode() < countof(threadLocalModes));
	assert((size_t)fn->getLinkage() < countof(linkageTypes));
	assert(fn->isDeclaration());
	
	size_t typeIndex = types.accumulate(fn->getFunctionType());
	auto& functionDeclarationLine = insert(fn);
	functionDeclarationLine << "llvm::Function::Create(types[" << typeIndex << "], " << linkageTypes[fn->getLinkage()] << ", \"";
	functionDeclarationLine.write_escaped(fn->getName());
	functionDeclarationLine << "\", module);";
}

global_dumper::global_dumper(synthesized_class& klass, type_dumper& types)
: types(types), method(klass.new_method("void", "make_globals")), resizeLine(method.nl())
{
	method.nl() = "using namespace llvm;";
	klass.new_field("std::vector<llvm::GlobalValue*>", "globals");
	klass.ctor_nl() = "make_globals();";
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

size_t global_dumper::accumulate(Function *fn)
{
	auto iter = var_indices.find(fn);
	if (iter == var_indices.end())
	{
		make_global(fn);
		return var_indices[fn];
	}
	return iter->second;
}
