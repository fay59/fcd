//
//  constant_dumper.cpp
//  interpiler
//
//  Created by Félix on 2015-04-11.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include "dump_constant.h"

#include <iomanip>
#include <llvm/IR/Constants.h>
#include <llvm/Support/raw_ostream.h>
#include <unordered_map>
#include <string>
#include <sstream>

using namespace std;
using namespace llvm;

namespace
{
	constexpr char nl = '\n';
	
	constexpr char boolstring[2][6] = {
		[false] = "false",
		[true] = "true",
	};
	
	string dump_aggregate(llvm::raw_ostream& into, type_dumper& types, const string& prefix, const string& typeName, Constant* constant)
	{
		unsigned count = constant->getNumOperands();
		vector<string> constantNames(count);
		for (unsigned i = 0; i < count; i++)
		{
			string dumpPrefix = prefix;
			raw_string_ostream ss(dumpPrefix);
			ss << "item" << i << '_';
			ss.flush();
			constantNames[i] = dump_constant(into, types, dumpPrefix, constant->getAggregateElement(i));
		}
		
		into << '\t' << "llvm::ArrayRef<llvm::Constant*> " << prefix << "elems { ";
		for (const string& name : constantNames)
		{
			into << name << ", ";
		}
		into << "};" << nl;
		
		string valueName = prefix;
		raw_string_ostream ss(valueName);
		ss << char(tolower(typeName[0]));
		ss << typeName.substr(1);
		ss.flush();
		
		size_t index = types.accumulate(constant->getType());
		into << '\t' << "llvm::Constant* " << valueName << " = llvm::Constant" << typeName << "::get(types[" << index << "], " << prefix << "elems);" << nl;
		
		return valueName;
	}
	
	string dump_constant(llvm::raw_ostream& into, type_dumper& types, const string& prefix, BlockAddress* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(llvm::raw_ostream& into, type_dumper& types, const string& prefix, ConstantAggregateZero* constant)
	{
		size_t index = types.accumulate(constant->getType());
		into << '\t' << "llvm::Constant* " << prefix << "zero = llvm::ConstantAggregateZero::get(types[" << index << "]);" << nl;
		return prefix + "zero";
	}
	
	string dump_constant(llvm::raw_ostream& into, type_dumper& types, const string& prefix, ConstantArray* constant)
	{
		return dump_aggregate(into, types, prefix, "Array", constant);
	}
	
	string dump_constant(llvm::raw_ostream& into, type_dumper& types, const string& prefix, ConstantDataArray* constant)
	{
		if (constant->isString())
		{
			into << '\t' << "llvm::Constant* " << prefix << "string = "
				<< "llvm::ConstantDataArray::getString(context, \"";
			into.write_escaped(constant->getAsCString());
			into << "\", true);" << nl;
			return prefix + "string";
		}
		
		bool isFloat = false;
		Type* elementType = constant->getElementType();
		into << '\t' << "llvm::ArrayRef<";
		if (IntegerType* intType = dyn_cast<IntegerType>(elementType))
		{
			into << "uint" << intType->getIntegerBitWidth() << "_t";
		}
		else if (elementType->isFloatingPointTy())
		{
			unsigned size = elementType->getPrimitiveSizeInBits();
			if (size == 16 || size == 32 || size == 64)
			{
				into << "uint" << size << "_t";
			}
			else
			{
				assert(!"not implemented");
				throw invalid_argument("elementType");
			}
			isFloat = true;
		}
		else
		{
			assert(!"not implemented");
			throw invalid_argument("elementType");
		}
		
		into << "> " << prefix << "array = { ";
		for (unsigned i = 0; i < constant->getNumElements(); i++)
		{
			if (isFloat)
			{
				APInt fl = constant->getElementAsAPFloat(i).bitcastToAPInt();
				fl.print(into, false);
			}
			else
			{
				into << constant->getElementAsInteger(i);
			}
			into << ", ";
		}
		into << "};" << nl;
		into << '\t' << "llvm::Constant* " << prefix << "data = llvm::ConstantDataArray::get";
		if (isFloat)
		{
			into << "FP";
		}
		into << "(context, " << prefix << "data);" << nl;
		return prefix + "data";
	}
	
	string dump_constant(llvm::raw_ostream& into, type_dumper& types, const string& prefix, ConstantDataVector* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(llvm::raw_ostream& into, type_dumper& types, const string& prefix, ConstantExpr* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(llvm::raw_ostream& into, type_dumper& types, const string& prefix, ConstantFP* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(llvm::raw_ostream& into, type_dumper& types, const string& prefix, ConstantInt* constant)
	{
		size_t index = types.accumulate(constant->getType());
		into << '\t' << "llvm::Constant* " << prefix << "int = llvm::ConstantInt::get(types[" << index << "], ";
		APInt value = constant->getValue();
		value.print(into, false);
		into << ");" << nl;
		return prefix + "int";
	}
	
	string dump_constant(llvm::raw_ostream& into, type_dumper& types, const string& prefix, ConstantPointerNull* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(llvm::raw_ostream& into, type_dumper& types, const string& prefix, ConstantStruct* constant)
	{
		return dump_aggregate(into, types, prefix, "Struct", constant);
	}
	
	string dump_constant(llvm::raw_ostream& into, type_dumper& types, const string& prefix, ConstantVector* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(llvm::raw_ostream& into, type_dumper& types, const string& prefix, UndefValue* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
}

string dump_constant(llvm::raw_ostream& into, type_dumper& types, const string& prefix, Constant* constant)
{
	if (auto c = dyn_cast<BlockAddress>(constant)) return dump_constant(into, types, prefix, c);
	if (auto c = dyn_cast<ConstantAggregateZero>(constant)) return dump_constant(into, types, prefix, c);
	if (auto c = dyn_cast<ConstantArray>(constant)) return dump_constant(into, types, prefix, c);
	if (auto c = dyn_cast<ConstantDataArray>(constant)) return dump_constant(into, types, prefix, c);
	if (auto c = dyn_cast<ConstantDataVector>(constant)) return dump_constant(into, types, prefix, c);
	if (auto c = dyn_cast<ConstantExpr>(constant)) return dump_constant(into, types, prefix, c);
	if (auto c = dyn_cast<ConstantFP>(constant)) return dump_constant(into, types, prefix, c);
	if (auto c = dyn_cast<ConstantInt>(constant)) return dump_constant(into, types, prefix, c);
	if (auto c = dyn_cast<ConstantPointerNull>(constant)) return dump_constant(into, types, prefix, c);
	if (auto c = dyn_cast<ConstantStruct>(constant)) return dump_constant(into, types, prefix, c);
	if (auto c = dyn_cast<ConstantVector>(constant)) return dump_constant(into, types, prefix, c);
	if (auto c = dyn_cast<UndefValue>(constant)) return dump_constant(into, types, prefix, c);
	
	assert(!"not implemented");
	throw invalid_argument("constant");
}

llvm::raw_ostream& operator<<(llvm::raw_ostream& into, bool b)
{
	return into << boolstring[!!b];
}
