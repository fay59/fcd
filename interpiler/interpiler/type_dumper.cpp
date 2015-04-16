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
	void param_types(raw_ostream& output, const string& varName, const vector<size_t>& indices)
	{
		output << "ArrayRef<Type*> " << varName << " = { ";
		for (size_t index : indices)
		{
			output << "types[" << index << "], ";
		}
		output << "};";
	}
}

raw_ostream& type_dumper::new_line()
{
	ostream.reset(new raw_string_ostream(method.nl()));
	return *ostream;
}

raw_ostream& type_dumper::insert(Type *type)
{
	size_t index = type_indices.size();
	type_indices[type] = index;
	
	resizeLine.clear();
	(raw_string_ostream(resizeLine) << "types.resize(" << type_indices.size() << ");");
	
	return new_line() << "types[" << index << "] = ";
}

void type_dumper::make_dump(SequentialType* type, const string& typeName, uint64_t subclassData)
{
	size_t elementIndex = accumulate(type->getElementType());
	insert(type) << typeName << "Type::get(types[" << elementIndex << "], " << subclassData << ");";
}

void type_dumper::make_dump(Type* type, const string& typeMethod)
{
	insert(type) << "Type::get" << typeMethod << "Ty(context);";
}

void type_dumper::make_dump(IntegerType* type)
{
	insert(type) << "IntegerType::get(context, " << type->getBitWidth() << ");";
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
	param_types(new_line(), typeParamsVar, typeIndices);
	
	size_t returnTypeIndex = accumulate(type->getReturnType());
	insert(type) << "FunctionType::get(types[" << returnTypeIndex << "], " << typeParamsVar << ", " << type->isVarArg() << ");";
}

void type_dumper::make_dump(StructType* type)
{
	size_t self_index = type_indices.size();
	raw_ostream& typeDeclLine = new_line();
	typeDeclLine << "StructType* struct_" << self_index << " = StructType::create(context";
	if (type->hasName())
	{
		typeDeclLine << ", \"";
		typeDeclLine.write_escaped(type->getName());
		typeDeclLine << '"';
	}
	typeDeclLine << ");";
	insert(type) << "struct_" << self_index << ";";
	
	vector<size_t> typeIndices;
	for (auto iter = type->element_begin(); iter != type->element_end(); iter++)
	{
		typeIndices.push_back(accumulate(*iter));
	}
	
	stringstream ss;
	ss << "struct_type_params_" << self_index;
	string typeParamsVar = ss.str();
	param_types(new_line(), typeParamsVar, typeIndices);
	new_line() << "struct_" << self_index << "->setBody(" << typeParamsVar << ", " << type->isPacked() << ");";
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

type_dumper::type_dumper(synthesized_class& klass)
: method(klass.new_method("void", "make_types")), resizeLine(method.nl())
{
	method.nl() = "using namespace llvm;";
	klass.new_field("std::vector<llvm::Type*>", "types");
	klass.ctor_nl() = "make_types();";
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
