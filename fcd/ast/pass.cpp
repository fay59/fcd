//
// pass.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "pass.h"

using namespace std;

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
			this->fn = fn.get();
			doRun(*fn);
		}
	}
}
