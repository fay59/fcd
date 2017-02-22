//
// function.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "function.h"
#include "metadata.h"
#include "print.h"

#include <llvm/IR/CFG.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_os_ostream.h>

#include <memory>

using namespace llvm;
using namespace std;

void FunctionNode::print(llvm::raw_ostream &os)
{
	const ExpressionType& returnType = context.getType(*function.getReturnType());
	FunctionExpressionType& functionType = context.createFunction(returnType);
	for (Argument& arg : function.args())
	{
		string argName = arg.getName();
		if (argName.size() == 0 || argName[0] == '\0')
		{
			raw_string_ostream(argName) << "arg" << arg.getArgNo();
		}
		functionType.append(context.getType(*arg.getType()), argName);
	}
	StatementPrintVisitor::declare(os, functionType, function.getName());
	
	if (hasBody())
	{
		os << '\n';
		StatementPrintVisitor::print(getContext(), os, *body);
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
