//
// function.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is part of fcd.
// 
// fcd is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// fcd is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with fcd.  If not, see <http://www.gnu.org/licenses/>.
//

#include "function.h"
#include "metadata.h"
#include "print.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/CFG.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <memory>

using namespace llvm;
using namespace std;

namespace
{
	inline void printTypeAsC(raw_ostream& os, Type* type)
	{
		if (type->isVoidTy())
		{
			os << "void";
			return;
		}
		if (type->isIntegerTy())
		{
			size_t width = type->getIntegerBitWidth();
			if (width == 1)
			{
				os << "bool";
			}
			else
			{
				// HACKHACK: this will not do if we ever want to differentiate signed and unsigned values
				os << "int" << width << "_t";
			}
			return;
		}
		if (type->isPointerTy())
		{
			// HACKHACK: this will not do once LLVM gets rid of pointer types
			printTypeAsC(os, type->getPointerElementType());
			os << '*';
			return;
		}
		if (auto arrayType = dyn_cast<ArrayType>(type))
		{
			printTypeAsC(os, arrayType->getElementType());
			os << '[' << arrayType->getNumElements() << ']';
			return;
		}
		if (auto structType = dyn_cast<StructType>(type))
		{
			os << '{';
			unsigned elems = structType->getNumElements();
			if (elems > 0)
			{
				printTypeAsC(os, structType->getElementType(0));
				for (unsigned i = 1; i < elems; ++i)
				{
					os << ", ";
					printTypeAsC(os, structType->getElementType(i));
				}
			}
			os << '}';
			return;
		}
		if (auto fnType = dyn_cast<FunctionType>(type))
		{
			printTypeAsC(os, fnType->getReturnType());
			os << '(';
			unsigned elems = fnType->getNumParams();
			if (elems > 0)
			{
				printTypeAsC(os, fnType->getParamType(0));
				for (unsigned i = 1; i < elems; ++i)
				{
					os << ", ";
					printTypeAsC(os, fnType->getParamType(i));
				}
			}
			os << ')';
			return;
		}
		llvm_unreachable("implement me");
	}
}

void FunctionNode::printIntegerConstant(llvm::raw_ostream &os, uint64_t integer)
{
	if (integer > 0xffff)
	{
		(os << "0x").write_hex(integer);
	}
	else
	{
		os << integer;
	}
}

void FunctionNode::printIntegerConstant(llvm::raw_ostream &&os, uint64_t integer)
{
	printIntegerConstant(os, integer);
}

void FunctionNode::printPrototype(llvm::raw_ostream &os, llvm::Function &function, llvm::Type* returnType)
{
	auto type = function.getFunctionType();
	printTypeAsC(os, returnType ? returnType : type->getReturnType());
	os << ' ' << function.getName() << '(';
	auto iter = function.arg_begin();
	if (iter != function.arg_end())
	{
		printTypeAsC(os, iter->getType());
		StringRef argName = iter->getName();
		if (argName != "")
		{
			os << ' ' << iter->getName();
		}
		iter++;
		while (iter != function.arg_end())
		{
			os << ", ";
			printTypeAsC(os, iter->getType());
			argName = iter->getName();
			if (argName != "")
			{
				os << ' ' << iter->getName();
			}
			iter++;
		}
		
		if (function.isVarArg())
		{
			os << ", ";
		}
	}
	else
	{
		os << "void";
	}
	
	if (function.isVarArg())
	{
		os << "...";
	}
	
	os << ')';
}

SequenceStatement* FunctionNode::basicBlockToStatement(llvm::BasicBlock &bb)
{
	SequenceStatement* sequence = context.sequence();
	// Translate instructions.
	for (Instruction& inst : bb)
	{
		if (Statement* statement = context.statementFor(inst))
		{
			sequence->pushBack(statement);
		}
	}
	
	// Add phi value assignments.
	for (BasicBlock* successor : successors(&bb))
	{
		for (auto phiIter = successor->begin(); PHINode* phi = dyn_cast<PHINode>(phiIter); phiIter++)
		{
			auto assignTo = valueFor(*phi);
			auto phiValue = valueFor(*phi->getIncomingValueForBlock(&bb));
			auto assignment = context.nary(NAryOperatorExpression::Assign, assignTo, phiValue);
			auto statement = context.expr(assignment);
			sequence->pushBack(statement);
		}
	}
	
	return sequence;
}

void FunctionNode::print(llvm::raw_ostream &os)
{
	printPrototype(os, function, &getReturnType());
	if (hasBody())
	{
		os << "\n{\n";
		StatementPrintVisitor::print(getContext(), os, *body);
		os << "}\n";
	}
	else
	{
		os << ";\n";
	}
}

void FunctionNode::dump() const
{
	const_cast<FunctionNode*>(this)->print(errs());
}
