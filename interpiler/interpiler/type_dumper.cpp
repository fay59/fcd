//
//  type_dumper.cpp
//  interpiler
//
//  Created by Félix on 2015-04-11.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include "dump_constant.h"
#include "type_dumper.h"

#include <iomanip>
#include <sstream>
#include <vector>

using namespace std;
using namespace llvm;

namespace
{
	constexpr char nl = '\n';
	
	void param_types(llvm::raw_ostream& output, const string& varName, const vector<size_t>& indices)
	{
		output << '\t' << "llvm::ArrayRef<llvm::Type*> " << varName << " = { ";
		for (size_t index : indices)
		{
			output << "types[" << index << "], ";
		}
		output << "};" << nl;
	}
}

llvm::raw_ostream& type_dumper::insert(llvm::Type *type)
{
	size_t index = type_indices.size();
	type_indices[type] = index;
	return method_body << '\t' << "types[" << index << "] = ";
}

void type_dumper::make_dump(SequentialType* type, const string& typeName, uint64_t subclassData)
{
	size_t elementIndex = accumulate(type->getElementType());
	insert(type) << "llvm::" << typeName << "Type::get(types[" << elementIndex << "], " << subclassData << ");" << nl;
}

void type_dumper::make_dump(Type* type, const string& typeMethod)
{
	insert(type) << "llvm::Type::get" << typeMethod << "Ty(ctx);" << nl;
}

void type_dumper::make_dump(IntegerType* type)
{
	insert(type) << "llvm::IntegerType::get(ctx, " << type->getBitWidth() << ");" << nl;
}

void type_dumper::make_dump(ArrayType* type)
{
	make_dump(type, "Array", type->getNumElements());
}

void type_dumper::make_dump(PointerType* type)
{
	make_dump(type, "Pointer", type->getAddressSpace());
}

void type_dumper::make_dump(VectorType* type)
{
	make_dump(type, "Vector", type->getNumElements());
}

void type_dumper::make_dump(FunctionType* type)
{
	vector<size_t> typeIndices;
	for (auto iter = type->param_begin(); iter != type->param_end(); iter++)
	{
		typeIndices.push_back(accumulate(*iter));
	}
	
	size_t self_index = type_indices.size();
	stringstream ss;
	ss << "func_type_params_" << self_index;
	string typeParamsVar = ss.str();
	param_types(method_body, typeParamsVar, typeIndices);
	
	size_t returnTypeIndex = accumulate(type->getReturnType());
	insert(type) << "llvm::FunctionType::get(types[" << returnTypeIndex << "], " << typeParamsVar << ", " << type->isVarArg() << ");" << nl;
}

void type_dumper::make_dump(StructType* type)
{
	size_t self_index = type_indices.size();
	method_body << '\t' << "llvm::StructType* struct_" << self_index << " = llvm::StructType::create(ctx";
	if (type->hasName())
	{
		method_body << ", \"";
		method_body.write_escaped(type->getName());
		method_body << '"';
	}
	method_body << ");" << nl;
	insert(type) << "struct_" << self_index << ";" << nl;
	
	vector<size_t> typeIndices;
	for (auto iter = type->element_begin(); iter != type->element_end(); iter++)
	{
		typeIndices.push_back(accumulate(*iter));
	}
	
	stringstream ss;
	ss << "struct_type_params_" << self_index;
	string typeParamsVar = ss.str();
	param_types(method_body, typeParamsVar, typeIndices);
	method_body << '\t' << "struct_" << self_index << "->setBody(" << typeParamsVar << ", " << type->isPacked() << ");" << nl;
}

void type_dumper::make_dump(Type* type)
{
	if (type->isVoidTy()) return make_dump(type, "Void");
	if (type->isLabelTy()) return make_dump(type, "Label");
	if (type->isHalfTy()) return make_dump(type, "Half");
	if (type->isFloatTy()) return make_dump(type, "Float");
	if (type->isDoubleTy()) return make_dump(type, "Double");
	if (type->isMetadataTy()) return make_dump(type, "Metadata");
	if (type->isX86_FP80Ty()) return make_dump(type, "X86_FP80");
	if (type->isFP128Ty()) return make_dump(type, "FP128");
	if (type->isPPC_FP128Ty()) return make_dump(type, "PPC_FP128");
	if (type->isX86_MMXTy()) return make_dump(type, "X86_MMX");
	
	if (auto t = dyn_cast<IntegerType>(type)) return make_dump(t);
	if (auto t = dyn_cast<ArrayType>(type)) return make_dump(t);
	if (auto t = dyn_cast<PointerType>(type)) return make_dump(t);
	if (auto t = dyn_cast<VectorType>(type)) return make_dump(t);
	if (auto t = dyn_cast<FunctionType>(type)) return make_dump(t);
	if (auto t = dyn_cast<StructType>(type)) return make_dump(t);
	
	throw invalid_argument("unknown type type");
}

type_dumper::type_dumper()
: method_body(body)
{
}

size_t type_dumper::accumulate(Type* type)
{
	auto iter = type_indices.find(type);
	if (iter == type_indices.end())
	{
		make_dump(type);
		return type_indices[type];
	}
	return iter->second;
}

size_t type_dumper::index_of(Type *type) const
{
	auto iter = type_indices.find(type);
	if (iter == type_indices.end())
	{
		return npos;
	}
	return iter->second;
}

string type_dumper::get_function_body(const string &functionName) const
{
	method_body.flush();
	
	string result;
	raw_string_ostream ss(result);
	ss << "void " << functionName << "()" << nl;
	ss << '{' << nl;
	ss << '\t' << "types.resize(" << type_indices.size() << ");" << nl;
	ss << body;
	ss << '}' << nl;
	ss.flush();
	return result;
}
