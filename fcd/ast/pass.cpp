//
// pass.cpp
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

#include "pass.h"

using namespace llvm;
using namespace std;

namespace
{
	void pushAll(SequenceNode& to, Statement& ref)
	{
		if (auto seq = dyn_cast<SequenceNode>(&ref))
		{
			to.statements.push_back(seq->statements.begin(), seq->statements.end());
		}
		else
		{
			to.statements.push_back(&ref);
		}
	}
}

Expression* AstFunctionPass::negate(Expression* toNegate)
{
	if (auto unary = dyn_cast<UnaryOperatorExpression>(toNegate))
	if (unary->type == UnaryOperatorExpression::LogicalNegate)
	{
		return unary->operand;
	}
	return pool().allocate<UnaryOperatorExpression>(UnaryOperatorExpression::LogicalNegate, toNegate);
}

Expression* AstFunctionPass::append(NAryOperatorExpression::NAryOperatorType opcode, Expression* a, Expression* b)
{
	auto result = pool().allocate<NAryOperatorExpression>(pool(), opcode);
	result->addOperand(a, b);
	return result;
}

Statement* AstFunctionPass::append(Statement* a, Statement* b)
{
	if (a == nullptr)
	{
		return b;
	}
	
	if (b == nullptr)
	{
		return a;
	}
	
	SequenceNode* seq = pool().allocate<SequenceNode>(pool());
	pushAll(*seq, *a);
	pushAll(*seq, *b);
	return seq;
}

void AstModulePass::run(deque<unique_ptr<FunctionNode>>& fn)
{
	if (fn.size() > 0)
	{
		doRun(fn);
	}
}

void AstFunctionPass::doRun(deque<unique_ptr<FunctionNode>>& list)
{
	for (unique_ptr<FunctionNode>& fn : list)
	{
		if (fn->hasBody())
		{
			pool_ = &fn->pool;
			doRun(*fn);
		}
	}
}
