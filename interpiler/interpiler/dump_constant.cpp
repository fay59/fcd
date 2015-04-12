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
	
	string dump_constant(llvm::raw_ostream& into, const string& prefix, BlockAddress* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(llvm::raw_ostream& into, const string& prefix, ConstantAggregateZero* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(llvm::raw_ostream& into, const string& prefix, ConstantArray* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(llvm::raw_ostream& into, const string& prefix, ConstantDataArray* constant)
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
	
	string dump_constant(llvm::raw_ostream& into, const string& prefix, ConstantDataVector* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(llvm::raw_ostream& into, const string& prefix, ConstantExpr* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(llvm::raw_ostream& into, const string& prefix, ConstantFP* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(llvm::raw_ostream& into, const string& prefix, ConstantInt* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(llvm::raw_ostream& into, const string& prefix, ConstantPointerNull* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(llvm::raw_ostream& into, const string& prefix, ConstantStruct* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(llvm::raw_ostream& into, const string& prefix, ConstantVector* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
	
	string dump_constant(llvm::raw_ostream& into, const string& prefix, UndefValue* constant)
	{
		assert(!"not implemented");
		throw invalid_argument("constant");
	}
}

string dump_constant(llvm::raw_ostream& into, const string& prefix, Constant* constant)
{
	if (auto c = dyn_cast<BlockAddress>(constant)) return dump_constant(into, prefix, c);
	if (auto c = dyn_cast<ConstantAggregateZero>(constant)) return dump_constant(into, prefix, c);
	if (auto c = dyn_cast<ConstantArray>(constant)) return dump_constant(into, prefix, c);
	if (auto c = dyn_cast<ConstantDataArray>(constant)) return dump_constant(into, prefix, c);
	if (auto c = dyn_cast<ConstantDataVector>(constant)) return dump_constant(into, prefix, c);
	if (auto c = dyn_cast<ConstantExpr>(constant)) return dump_constant(into, prefix, c);
	if (auto c = dyn_cast<ConstantFP>(constant)) return dump_constant(into, prefix, c);
	if (auto c = dyn_cast<ConstantInt>(constant)) return dump_constant(into, prefix, c);
	if (auto c = dyn_cast<ConstantPointerNull>(constant)) return dump_constant(into, prefix, c);
	if (auto c = dyn_cast<ConstantStruct>(constant)) return dump_constant(into, prefix, c);
	if (auto c = dyn_cast<ConstantVector>(constant)) return dump_constant(into, prefix, c);
	if (auto c = dyn_cast<UndefValue>(constant)) return dump_constant(into, prefix, c);
	
	assert(!"not implemented");
	throw invalid_argument("constant");
}

llvm::raw_ostream& operator<<(llvm::raw_ostream& into, bool b)
{
	return into << boolstring[!!b];
}
