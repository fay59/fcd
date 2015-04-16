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
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/Support/raw_ostream.h>
#include <unordered_map>
#include <string>
#include <sstream>

using namespace std;
using namespace llvm;

namespace
{
	constexpr char boolstring[2][6] = {
		[false] = "false",
		[true] = "true",
	};
	
	string dump_aggregate_values(synthesized_method& into, type_dumper& types, const string& prefix, Constant* constant)
	{
		unsigned count = constant->getNumOperands();
		vector<string> constantNames(count);
		for (unsigned i = 0; i < count; i++)
		{
			string dumpPrefix = prefix;
			raw_string_ostream(dumpPrefix) << "item" << i << '_';
			constantNames[i] = dump_constant(into, types, dumpPrefix, constant->getAggregateElement(i));
		}
		
		raw_string_ostream ss(into.nl());
		ss << "ArrayRef<Constant*> " << prefix << "elems { ";
		for (const string& name : constantNames)
		{
			ss << name << ", ";
		}
		ss << "};";
		return prefix + "elems";
	}
	
	string dump_aggregate(synthesized_method& into, type_dumper& types, const string& prefix, const string& typeName, Constant* constant)
	{
		string arrayName = dump_aggregate_values(into, types, prefix, constant);
		
		string valueName = prefix;
		raw_string_ostream(valueName) << char(tolower(typeName[0])) << typeName.substr(1);
		
		raw_string_ostream ss(into.nl());
		size_t index = types.accumulate(constant->getType());
		ss << "Constant* " << valueName << " = Constant" << typeName << "::get(types[" << index << "], " << arrayName << ");";
		
		return valueName;
	}
	
	string dump_data_sequential(synthesized_method& into, type_dumper& types, const string& prefix, const string& typeName, ConstantDataSequential* constant)
	{
		bool isFloat = false;
		Type* elementType = constant->getElementType();
		raw_string_ostream arrayLine(into.nl());
		arrayLine << "ArrayRef<";
		if (IntegerType* intType = dyn_cast<IntegerType>(elementType))
		{
			arrayLine << "uint" << intType->getIntegerBitWidth() << "_t";
		}
		else if (elementType->isFloatingPointTy())
		{
			unsigned size = elementType->getPrimitiveSizeInBits();
			if (size == 16 || size == 32 || size == 64)
			{
				arrayLine << "uint" << size << "_t";
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
		
		arrayLine << "> " << prefix << "array = { ";
		for (unsigned i = 0; i < constant->getNumElements(); i++)
		{
			if (isFloat)
			{
				APInt fl = constant->getElementAsAPFloat(i).bitcastToAPInt();
				fl.print(arrayLine, false);
			}
			else
			{
				arrayLine << constant->getElementAsInteger(i);
			}
			arrayLine << ", ";
		}
		arrayLine << "};";
		
		raw_string_ostream ss(into.nl());
		ss << "Constant* " << prefix << "data = ConstantData" << typeName << "::get";
		if (isFloat)
		{
			ss << "FP";
		}
		ss << "(context, " << prefix << "data);";
		return prefix + "data";
	}
	
	string dump_constant(synthesized_method& into, type_dumper& types, const string& prefix, BlockAddress* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(synthesized_method& into, type_dumper& types, const string& prefix, ConstantAggregateZero* constant)
	{
		size_t index = types.accumulate(constant->getType());
		raw_string_ostream(into.nl()) << "Constant* " << prefix << "zero = ConstantAggregateZero::get(types[" << index << "]);";
		return prefix + "zero";
	}
	
	string dump_constant(synthesized_method& into, type_dumper& types, const string& prefix, ConstantArray* constant)
	{
		return dump_aggregate(into, types, prefix, "Array", constant);
	}
	
	string dump_constant(synthesized_method& into, type_dumper& types, const string& prefix, ConstantDataArray* constant)
	{
		if (constant->isString())
		{
			raw_string_ostream ss(into.nl());
			ss << "Constant* " << prefix << "string = "
			<< "ConstantDataArray::getString(context, \"";
			ss.write_escaped(constant->getAsCString());
			ss << "\", true);";
			return prefix + "string";
		}
		
		return dump_data_sequential(into, types, prefix, "Array", constant);
	}
	
	string dump_constant(synthesized_method& into, type_dumper& types, const string& prefix, ConstantDataVector* constant)
	{
		if (Constant* splat = constant->getSplatValue())
		{
			string splatName = dump_constant(into, types, prefix + "splat", splat);
			
			raw_string_ostream(into.nl()) << "Constant* " << prefix << "splat = "
				<< "ConstantDataVector::getSplat(" << constant->getNumElements() << ", " << splatName << ");";
			return prefix + "splat";
		}
		
		return dump_data_sequential(into, types, prefix, "Vector", constant);
	}
	
	string dump_constant(synthesized_method& into, type_dumper& types, const string& prefix, ConstantFP* constant)
	{
		size_t index = types.accumulate(constant->getType());
		APFloat value = constant->getValueAPF();
		
		SmallVector<char, 32> string;
		value.toString(string, 0, 0);
		StringRef stringVal(string.data(), string.size());
		
		raw_string_ostream stringRefLine(into.nl());
		stringRefLine << "StringRef " << prefix << "string = \"";
		stringRefLine.write_escaped(stringVal);
		stringRefLine << "\";";
		
		raw_string_ostream ss(into.nl());
		ss << "Constant* " << prefix << "fp = ConstantFP::get(types[" << index << "], " << prefix << "string);";
		return prefix + "fp";
	}
	
	string dump_constant(synthesized_method& into, type_dumper& types, const string& prefix, ConstantInt* constant)
	{
		size_t index = types.accumulate(constant->getType());
		
		raw_string_ostream ss(into.nl());
		ss << "Constant* " << prefix << "int = ConstantInt::get(types[" << index << "], ";
		APInt value = constant->getValue();
		value.print(ss, false);
		ss << ");";
		
		return prefix + "int";
	}
	
	string dump_constant(synthesized_method& into, type_dumper& types, const string& prefix, ConstantPointerNull* constant)
	{
		size_t index = types.accumulate(constant->getType());
		raw_string_ostream(into.nl()) << "Constant* " << prefix << "null = ConstantPointerNull::get(types[" << index << "]);";
		return prefix + "null";
	}
	
	string dump_constant(synthesized_method& into, type_dumper& types, const string& prefix, ConstantStruct* constant)
	{
		return dump_aggregate(into, types, prefix, "Struct", constant);
	}
	
	string dump_constant(synthesized_method& into, type_dumper& types, const string& prefix, ConstantVector* constant)
	{
		if (Constant* splat = constant->getSplatValue())
		{
			string splatName = dump_constant(into, types, prefix + "splat", splat);
			
			raw_string_ostream(into.nl()) << "Constant* " << prefix << "splat = "
				<< "ConstantVector::getSplat(" << constant->getNumOperands() << ", " << splatName << ");";
			return prefix + "splat";
		}
		
		string arrayName = dump_aggregate_values(into, types, prefix, constant);
		raw_string_ostream(into.nl()) << "Constant* " << prefix << "vector = ConstantVector::get(" << arrayName << ");";
		return prefix + "vector";
	}
	
	string dump_constant(synthesized_method& into, type_dumper& types, const string& prefix, UndefValue* constant)
	{
		size_t index = types.accumulate(constant->getType());
		raw_string_ostream(into.nl()) << "Constant* " << prefix << "undef = UndefValue::get(types[" << index << "]);";
		return prefix + "undef";
	}
	
	string dump_constant(synthesized_method& into, type_dumper& types, const string& prefix, ConstantExpr* constant)
	{
		// Just making sure that my assumptions about the enum layout hold...
		
#define TEST_ENUM_BOUNDARIES(x, y) static_assert((int)Instruction::x == (int)Instruction::y, "enum values changed since LLVM 3.7 SVN trunk")
		static_assert((int)Instruction::TermOpsBegin == (int)1, "enum values changed since LLVM 3.7 SVN trunk");
		TEST_ENUM_BOUNDARIES(BinaryOpsBegin, TermOpsEnd);
		TEST_ENUM_BOUNDARIES(MemoryOpsBegin, BinaryOpsEnd);
		TEST_ENUM_BOUNDARIES(CastOpsBegin, MemoryOpsEnd);
		TEST_ENUM_BOUNDARIES(OtherOpsBegin, CastOpsEnd);
		static_assert((int)Instruction::OtherOpsEnd == (int)60, "enum values changed since LLVM 3.7 SVN trunk");
#undef TEST_ENUM_BOUNDARIES
		
		// I have no idea how to generate one of those. It's gonna be horrible to test, so instead I'll leave this here
		// until one comes my way.
		unsigned opcode = constant->getOpcode();
		if (opcode >= Instruction::OtherOpsBegin)
		{
			assert(!"not implemented");
			throw invalid_argument("constant");
		}
		if (opcode >= Instruction::CastOpsBegin)
		{
			assert(!"not implemented");
			throw invalid_argument("constant");
		}
		if (opcode >= Instruction::MemoryOpsBegin)
		{
			assert(!"not implemented");
			throw invalid_argument("constant");
		}
		if (opcode >= Instruction::BinaryOpsBegin)
		{
			assert(!"not implemented");
			throw invalid_argument("constant");
		}
		if (opcode >= Instruction::TermOpsBegin)
		{
			assert(!"not implemented");
			throw invalid_argument("constant");
		}
		
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
}

string dump_constant(synthesized_method& into, type_dumper& types, const string& prefix, Constant* constant)
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

raw_ostream& operator<<(raw_ostream& into, bool b)
{
	return into << boolstring[!!b];
}
