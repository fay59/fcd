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
	constexpr char nl = '\n';
	
	constexpr char boolstring[2][6] = {
		[false] = "false",
		[true] = "true",
	};
	
	string dump_aggregate_values(raw_ostream& into, type_dumper& types, const string& prefix, Constant* constant)
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
		return prefix + "elems";
	}
	
	string dump_aggregate(raw_ostream& into, type_dumper& types, const string& prefix, const string& typeName, Constant* constant)
	{
		string arrayName = dump_aggregate_values(into, types, prefix, constant);
		
		string valueName = prefix;
		raw_string_ostream ss(valueName);
		ss << char(tolower(typeName[0]));
		ss << typeName.substr(1);
		ss.flush();
		
		size_t index = types.accumulate(constant->getType());
		into << '\t' << "llvm::Constant* " << valueName << " = llvm::Constant" << typeName << "::get(types[" << index << "], " << arrayName << ");" << nl;
		
		return valueName;
	}
	
	string dump_data_sequential(raw_ostream& into, type_dumper& types, const string& prefix, const string& typeName, ConstantDataSequential* constant)
	{
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
		into << '\t' << "llvm::Constant* " << prefix << "data = llvm::ConstantData" << typeName << "::get";
		if (isFloat)
		{
			into << "FP";
		}
		into << "(context, " << prefix << "data);" << nl;
		return prefix + "data";
	}
	
	string dump_constant(raw_ostream& into, type_dumper& types, const string& prefix, BlockAddress* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(raw_ostream& into, type_dumper& types, const string& prefix, ConstantAggregateZero* constant)
	{
		size_t index = types.accumulate(constant->getType());
		into << '\t' << "llvm::Constant* " << prefix << "zero = llvm::ConstantAggregateZero::get(types[" << index << "]);" << nl;
		return prefix + "zero";
	}
	
	string dump_constant(raw_ostream& into, type_dumper& types, const string& prefix, ConstantArray* constant)
	{
		return dump_aggregate(into, types, prefix, "Array", constant);
	}
	
	string dump_constant(raw_ostream& into, type_dumper& types, const string& prefix, ConstantDataArray* constant)
	{
		if (constant->isString())
		{
			into << '\t' << "llvm::Constant* " << prefix << "string = "
			<< "llvm::ConstantDataArray::getString(context, \"";
			into.write_escaped(constant->getAsCString());
			into << "\", true);" << nl;
			return prefix + "string";
		}
		
		return dump_data_sequential(into, types, prefix, "Array", constant);
	}
	
	string dump_constant(raw_ostream& into, type_dumper& types, const string& prefix, ConstantDataVector* constant)
	{
		if (Constant* splat = constant->getSplatValue())
		{
			string splatName = dump_constant(into, types, prefix + "splat", splat);
			
			into << '\t' << "llvm::Constant* " << prefix << "splat = "
				<< "llvm::ConstantDataVector::getSplat(" << constant->getNumElements() << ", " << splatName << ");" << nl;
			return prefix + "splat";
		}
		
		return dump_data_sequential(into, types, prefix, "Vector", constant);
	}
	
	string dump_constant(raw_ostream& into, type_dumper& types, const string& prefix, ConstantFP* constant)
	{
		size_t index = types.accumulate(constant->getType());
		APFloat value = constant->getValueAPF();
		
		SmallVector<char, 32> string;
		value.toString(string, 0, 0);
		StringRef stringVal(string.data(), string.size());
		into << '\t' << "llvm::StringRef " << prefix << "string = \"";
		into.write_escaped(stringVal);
		into << "\";" << nl;
		into << '\t' << "llvm::Constant* " << prefix << "fp = llvm::ConstantFP::get(types[" << index << "], " << prefix << "string);" << nl;
		return prefix + "fp";
	}
	
	string dump_constant(raw_ostream& into, type_dumper& types, const string& prefix, ConstantInt* constant)
	{
		size_t index = types.accumulate(constant->getType());
		into << '\t' << "llvm::Constant* " << prefix << "int = llvm::ConstantInt::get(types[" << index << "], ";
		APInt value = constant->getValue();
		value.print(into, false);
		into << ");" << nl;
		return prefix + "int";
	}
	
	string dump_constant(raw_ostream& into, type_dumper& types, const string& prefix, ConstantPointerNull* constant)
	{
		size_t index = types.accumulate(constant->getType());
		into << '\t' << "llvm::Constant* " << prefix << "null = llvm::ConstantPointerNull::get(types[" << index << "]);" << nl;
		return prefix + "null";
	}
	
	string dump_constant(raw_ostream& into, type_dumper& types, const string& prefix, ConstantStruct* constant)
	{
		return dump_aggregate(into, types, prefix, "Struct", constant);
	}
	
	string dump_constant(raw_ostream& into, type_dumper& types, const string& prefix, ConstantVector* constant)
	{
		if (Constant* splat = constant->getSplatValue())
		{
			string splatName = dump_constant(into, types, prefix + "splat", splat);
			
			into << '\t' << "llvm::Constant* " << prefix << "splat = "
				<< "llvm::ConstantVector::getSplat(" << constant->getNumOperands() << ", " << splatName << ");" << nl;
			return prefix + "splat";
		}
		
		string arrayName = dump_aggregate_values(into, types, prefix, constant);
		into << '\t' << "llvm::Constant* " << prefix << "vector = llvm::ConstantVector::get(" << arrayName << ");" << nl;
		return prefix + "vector";
	}
	
	string dump_constant(raw_ostream& into, type_dumper& types, const string& prefix, UndefValue* constant)
	{
		size_t index = types.accumulate(constant->getType());
		into << '\t' << "llvm::Constant* " << prefix << "undef = llvm::UndefValue::get(types[" << index << "]);" << nl;
		return prefix + "undef";
	}
	
	string dump_constant(raw_ostream& into, type_dumper& types, const string& prefix, ConstantExpr* constant)
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
	
	string dump_constant(raw_ostream& into, type_dumper& types, const string& prefix, Function* f)
	{
		assert(f->isDeclaration() && "use function_dumper for definitions");
		string elems = dump_aggregate_values(into, types, prefix, f);
		size_t typeIndex = types.accumulate(f->getFunctionType());
		into << '\t' << "llvm::Function* " << prefix << "fn = llvm::FunctionType::Create(types[" << typeIndex << "], ";
		//into <<
		return "";
	}
}

string dump_constant(raw_ostream& into, type_dumper& types, const string& prefix, Constant* constant)
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
