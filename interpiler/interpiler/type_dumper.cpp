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
	
	template<typename TIter>
	void arrayref(type_dumper& dumper, TIter&& begin, TIter&& end, std::ostream& output)
	{
		output << "{ ";
		for (auto iter = begin; iter != end; iter++)
		{
			output << dumper.dump(*iter).local_reference << ", ";
		}
		output << "}";
	}
}

const dumped_item& type_dumper::make_dump(SequentialType* type, const string& typeName, uint64_t subclassData)
{
	stringstream ss;
	const string& elementType = dump(type->getElementType()).local_reference;
	ss << "llvm::" << typeName << "Type::get(" << elementType << ", " << subclassData << ")";
	
	intptr_t key = reinterpret_cast<intptr_t>(type);
	return emplace(key, ss.str());
}

const dumped_item& type_dumper::make_dump(Type* type, const string& typeMethod)
{
	stringstream ss;
	ss << "llvm::Type::get" << typeMethod << "Ty(" << llvm_context_name << ")";
	
	intptr_t key = reinterpret_cast<intptr_t>(type);
	return emplace(key, ss.str());
}

const dumped_item& type_dumper::make_dump(IntegerType* type)
{
	stringstream ss;
	ss << "llvm::IntegerType::get(" << llvm_context_name << ", " << type->getBitWidth() << ")";
	
	intptr_t key = reinterpret_cast<intptr_t>(type);
	return emplace(key, ss.str());
}

const dumped_item& type_dumper::make_dump(FunctionType* type)
{
	stringstream functionNameStream;
	functionNameStream << "make_func_type_" << dumps.size();
	auto functionName = functionNameStream.str();
	
	intptr_t key = reinterpret_cast<intptr_t>(type);
	auto& dumped = emplace(key, functionName + "(" + llvm_context_name + ")");
	
	stringstream def;
	def << "llvm::FunctionType* " << functionName << "(llvm::LLVMContext& " << llvm_context_name << ")";
	string decl = def.str() + ";";
	
	def << endl << "{" << endl;
	def << tab << "llvm::ArrayRef<llvm::Type*> parameters ";
	arrayref(*this, type->param_begin(), type->param_end(), def);
	def << ";" << endl;
	
	const string& returnType = dump(type->getReturnType()).local_reference;
	def << tab << "return llvm::FunctionType::get(" << returnType << ", parameters, " << boolalpha << type->isVarArg() << ");" << endl;
	def << "}" << endl;
	
	dumped.global_declaration = decl;
	dumped.global_definition = def.str();
	return dumped;
}

const dumped_item& type_dumper::make_dump(ArrayType* type)
{
	return make_dump(type, "Array", type->getNumElements());
}

const dumped_item& type_dumper::make_dump(PointerType* type)
{
	return make_dump(type, "Pointer", type->getAddressSpace());
}

const dumped_item& type_dumper::make_dump(VectorType* type)
{
	return make_dump(type, "Vector", type->getNumElements());
}

const dumped_item& type_dumper::make_dump(StructType* type)
{
	stringstream functionNameStream;
	functionNameStream << "make_struct_type_" << dumps.size();
	auto functionName = functionNameStream.str();
	
	stringstream def;
	def << "llvm::StructType* " << functionName << "(llvm::LLVMContext& " << llvm_context_name << ")";
	string decl = def.str() + ";";
	
	def << endl << "{" << endl;
	
	def << tab << "llvm::StructType* structType = llvm::StructType::create(" << llvm_context_name;
	if (type->hasName())
	{
		string safeName = c_escape(type->getName().str());
		def << ", \"" << safeName << "\"";
	}
	def << ");" << endl;
	
	// Temporarily use local reference name. This allows arrayref to properly handle recursive struct types,
	// like linked list nodes.
	intptr_t key = reinterpret_cast<intptr_t>(type);
	auto& dumped = emplace(key, "structType");
	
	def << tab << "llvm::ArrayRef<llvm::Type*> parameters ";
	arrayref(*this, type->element_begin(), type->element_end(), def);
	def << ";" << endl;
	
	// We can now set the function name as the local reference.
	dumped.local_reference = functionName + "(" + llvm_context_name + ")";
	
	def << tab << "structType->setBody(parameters, " << boolalpha << type->isPacked() << ");" << endl;
	def << tab << "return structType;" << endl;
	def << "}" << endl;
	
	dumped.global_declaration = decl;
	dumped.global_definition = def.str();
	return dumped;
}

const dumped_item& type_dumper::make_dump(Type* type)
{
	if (auto t = dyn_cast<IntegerType>(type)) return make_dump(t);
	if (auto t = dyn_cast<FunctionType>(type)) return make_dump(t);
	if (auto t = dyn_cast<ArrayType>(type)) return make_dump(t);
	if (auto t = dyn_cast<PointerType>(type)) return make_dump(t);
	if (auto t = dyn_cast<VectorType>(type)) return make_dump(t);
	if (auto t = dyn_cast<StructType>(type)) return make_dump(t);
	
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
	throw invalid_argument("unknown type type");
}

const dumped_item& type_dumper::dump(Type* type)
{
	intptr_t key = reinterpret_cast<intptr_t>(type);
	auto iter = dumps.find(key);
	if (iter == dumps.end())
	{
		return make_dump(type);
	}
	return iter->second;
}
