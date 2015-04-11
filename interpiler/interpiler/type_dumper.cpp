//
//  type_dumper.cpp
//  interpiler
//
//  Created by Félix on 2015-04-11.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include "type_dumper.h"
#include <iomanip>
#include <sstream>
#include <vector>

using namespace std;
using namespace llvm;

namespace
{
	constexpr char tab = '\t';
	
	const unordered_map<char, string> c_escapes {
		make_pair('\0', "\\0"),
		make_pair('\b', "\\b"),
		make_pair('\t', "\\t"),
		make_pair('\n', "\\n"),
		make_pair('\r', "\\r"),
		make_pair('"', "\\\""),
	};
	
	string c_escape(const string& that)
	{
		stringstream ss;
		for (char c : that)
		{
			if (c < ' ' || c > 0x7f)
			{
				auto iter = c_escapes.find(c);
				if (iter == c_escapes.end())
				{
					ss << setw(2) << hex << setfill('0') << "\\x" << c;
				}
				else
				{
					ss << iter->second;
				}
			}
			else
			{
				ss << c;
			}
		}
		return ss.str();
	}
	
	void param_types(ostream& output, const string& varName, const vector<size_t>& indices)
	{
		output << '\t' << "llvm::ArrayRef<llvm::Type*> " << varName << " = { ";
		for (size_t index : indices)
		{
			output << "types[" << index << "], ";
		}
		output << "};" << endl;
	}
}

ostream& type_dumper::insert(llvm::Type *type)
{
	size_t index = type_indices.size();
	type_indices[type] = index;
	return method_body << '\t' << "types[" << index << "] = ";
}

void type_dumper::make_dump(SequentialType* type, const string& typeName, uint64_t subclassData)
{
	size_t elementIndex = accumulate(type->getElementType());
	insert(type) << "llvm::" << typeName << "Type::get(types[" << elementIndex << "], " << subclassData << ")" << endl;
}

void type_dumper::make_dump(Type* type, const string& typeMethod)
{
	insert(type) << "llvm::Type::get" << typeMethod << "Ty(ctx)" << endl;
}

void type_dumper::make_dump(IntegerType* type)
{
	insert(type) << "llvm::IntegerType::get(ctx, " << type->getBitWidth() << ")" << endl;
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
	insert(type) << "llvm::FunctionType::get(types[" << returnTypeIndex << "], " << typeParamsVar << ", " << boolalpha << type->isVarArg() << ");" << endl;
}

void type_dumper::make_dump(StructType* type)
{
	size_t self_index = type_indices.size();
	method_body << '\t' << "llvm::StructType* struct_" << self_index << " = llvm::StructType::create(ctx";
	if (type->hasName())
	{
		string safeName = c_escape(type->getName().str());
		method_body << ", \"" << safeName << "\"";
	}
	method_body << ");" << endl;
	insert(type) << "struct_" << self_index << ";" << endl;
	
	vector<size_t> typeIndices;
	for (auto iter = type->element_begin(); iter != type->element_end(); iter++)
	{
		typeIndices.push_back(accumulate(*iter));
	}
	
	stringstream ss;
	ss << "struct_type_params_" << self_index;
	string typeParamsVar = ss.str();
	param_types(method_body, typeParamsVar, typeIndices);
	method_body << '\t' << "struct_" << self_index << "->setBody(" << typeParamsVar << ", " << boolalpha << type->isPacked() << ");" << endl;
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

string type_dumper::get_function_body(const string &functionName) const
{
	stringstream ss;
	ss << "std::vector<llvm::Type*> " << functionName << "(llvm::LLVMContext& ctx)" << endl;
	ss << '{' << endl;
	ss << '\t' << "std::vector<llvm::Type*> types(" << type_indices.size() << ");" << endl;
	ss << method_body.str();
	ss << '\t' << "return types;" << endl;
	ss << '}' << endl;
	return ss.str();
}
