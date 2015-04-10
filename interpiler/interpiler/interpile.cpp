//
//  interpile.cpp
//  interpiler
//
//  Created by Félix on 2015-04-09.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include <memory>
#include <iostream>
#include <sstream>
#include <unordered_map>

using namespace llvm;
using namespace std;

void interpile(LLVMContext& context, unique_ptr<Module> module, ostream& header, ostream& impl);

namespace
{
	char tab = '\t';
	
	struct dumped_item
	{
		string global_declaration;
		string global_definition;
		string local_reference;
		
		dumped_item() = default;
		
		dumped_item(const string& local)
		: local_reference(local)
		{
		}
		
		dumped_item(const string& local, const string& global_decl, const string& global_def)
		: global_declaration(global_decl), global_definition(global_def)
		{
		}
		
	};
	
	class dumper
	{
	public:
		typedef unordered_map<intptr_t, dumped_item> collection_type;
		
	private:
		string llvm_context_name;
		collection_type dumps;
		
		template<typename TIter>
		void arrayref(TIter&& begin, TIter&& end, ostream& output)
		{
			output << "{ ";
			for (auto iter = begin; iter != end; iter++)
			{
				output << dump(*iter).local_reference << ", ";
			}
			output << "}";
		}
		
		dumped_item& emplace(intptr_t key, const string& local)
		{
			return dumps.emplace(make_pair(key, dumped_item(local))).first->second;
		}
		
		const dumped_item& emplace(intptr_t key, const string& local, const string& global_def, const string& global_decl)
		{
			return dumps.emplace(make_pair(key, dumped_item(local, global_def, global_decl))).first->second;
		}
		
		const dumped_item& make_dump(SequentialType* type, const string& typeName, uint64_t subclassData)
		{
			stringstream ss;
			const string& elementType = dump(type->getElementType()).local_reference;
			ss << "llvm::" << typeName << "Type::get(" << elementType << ", " << subclassData << ")";
			
			intptr_t key = reinterpret_cast<intptr_t>(type);
			return emplace(key, ss.str());
		}
		
		const dumped_item& make_dump(Type* type, const string& typeMethod)
		{
			stringstream ss;
			ss << "llvm::Type::get" << typeMethod << "Ty(" << llvm_context_name << ")";
			
			intptr_t key = reinterpret_cast<intptr_t>(type);
			return emplace(key, ss.str());
		}
		
		const dumped_item& make_dump(IntegerType* type)
		{
			stringstream ss;
			ss << "llvm::IntegerType::get(" << llvm_context_name << ", " << type->getBitWidth() << ")";
			
			intptr_t key = reinterpret_cast<intptr_t>(type);
			return emplace(key, ss.str());
		}
		
		const dumped_item& make_dump(FunctionType* type)
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
			arrayref(type->param_begin(), type->param_end(), def);
			def << ";" << endl;
			
			const string& returnType = dump(type->getReturnType()).local_reference;
			def << tab << "return llvm::FunctionType::get(" << returnType << ", parameters, " << boolalpha << type->isVarArg() << ");" << endl;
			def << "}" << endl;
			
			dumped.global_declaration = decl;
			dumped.global_definition = def.str();
			return dumped;
		}
		
		const dumped_item& make_dump(ArrayType* type)
		{
			return make_dump(type, "Array", type->getNumElements());
		}
		
		const dumped_item& make_dump(PointerType* type)
		{
			return make_dump(type, "Pointer", type->getAddressSpace());
		}
		
		const dumped_item& make_dump(VectorType* type)
		{
			return make_dump(type, "Vector", type->getNumElements());
		}
		
		const dumped_item& make_dump(StructType* type)
		{
			stringstream functionNameStream;
			functionNameStream << "make_struct_type_" << dumps.size();
			auto functionName = functionNameStream.str();
			
			intptr_t key = reinterpret_cast<intptr_t>(type);
			auto& dumped = emplace(key, functionName + "(" + llvm_context_name + ")");
			
			stringstream def;
			def << "llvm::StructType* " << functionName << "(llvm::LLVMContext& " << llvm_context_name << ")";
			string decl = def.str() + ";";
			
			def << endl << "{" << endl;
			def << tab << "llvm::ArrayRef<llvm::Type*> parameters ";
			arrayref(type->element_begin(), type->element_end(), def);
			def << ";" << endl;
			
			def << tab << "return llvm::StructType::get(" << llvm_context_name << ", parameters, " << boolalpha << type->isPacked() << ");" << endl;
			def << "}" << endl;
			
			dumped.global_declaration = decl;
			dumped.global_definition = def.str();
			return dumped;
		}
		
		const dumped_item& make_dump(Type* type)
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
		
	public:
		dumper(const string& ctxname)
			: llvm_context_name(ctxname)
		{
		}
		
		const dumped_item& dump(Type* type)
		{
			intptr_t key = reinterpret_cast<intptr_t>(type);
			auto iter = dumps.find(key);
			if (iter == dumps.end())
			{
				return make_dump(type);
			}
			return iter->second;
		}
		
		collection_type::iterator begin()
		{
			return dumps.begin();
		}
		
		collection_type::iterator end()
		{
			return dumps.end();
		}
	};
}

void interpile(LLVMContext& context, unique_ptr<Module> module, const string& class_name, ostream& header, ostream& impl)
{
	class dumper dumper("context");
	for (const GlobalVariable& var : module->getGlobalList())
	{
		dumper.dump(var.getType());
	}
	
	for (const Function& func : module->getFunctionList())
	{
		dumper.dump(func.getType());
	}
	
	for (const auto& pair : dumper)
	{
		const string& decl = pair.second.global_declaration;
		if (decl.length() > 0)
		{
			cout << decl << endl;
		}
	}
	
	cout << endl;
	for (const auto& pair : dumper)
	{
		const string& def = pair.second.global_definition;
		if (def.length() > 0)
		{
			cout << def << endl;
		}
	}
	
	cout << endl << '{' << endl;
	for (const auto& pair : dumper)
	{
		const string& local = pair.second.local_reference;
		if (local.length() > 0)
		{
			cout << tab << local << ";" << endl;
		}
	}
	cout << '}' << endl;
}
