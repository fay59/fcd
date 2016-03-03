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
	const ExpressionType& returnType = context.getType(*function.getReturnType());
	FunctionExpressionType& functionType = context.createFunction(returnType);
	for (Argument& arg : function.args())
	{
		functionType.append(context.getType(*arg.getType()), arg.getName());
	}
	StatementPrintVisitor::declare(os, functionType, function.getName());
	
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
