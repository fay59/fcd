//
// pass.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "pass.h"

#include <llvm/Support/PrettyStackTrace.h>

using namespace llvm;
using namespace std;

namespace
{
	void getUsingStatements(unordered_set<Statement*>& set, Expression* expr)
	{
		for (auto& use : expr->uses())
		{
			if (auto statement = dyn_cast<Statement>(use.getUser()))
			{
				set.insert(statement);
			}
			else if (auto expression = dyn_cast<Expression>(use.getUser()))
			{
				getUsingStatements(set, expression);
			}
		}
	}
}

unordered_set<Statement*> AstModulePass::getUsingStatements(Expression& expr)
{
	unordered_set<Statement*> statements;
	::getUsingStatements(statements, &expr);
	return statements;
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
		if (runOnDeclarations || fn->hasBody())
		{
			PrettyStackTraceFormat runPass("Running AST pass \"%s\" on function \"%s\"", getName(), string(fn->getFunction().getName()).c_str());
			
			this->fn = fn.get();
			doRun(*fn);
		}
	}
}
