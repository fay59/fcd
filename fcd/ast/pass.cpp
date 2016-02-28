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
	void pushAll(SequenceStatement& to, Statement& ref)
	{
		if (auto seq = dyn_cast<SequenceStatement>(&ref))
		{
			to.takeAllFrom(*seq);
		}
		else
		{
			to.pushBack(&ref);
		}
	}
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
	
	SequenceStatement* seq = context().sequence();
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
		if (runOnDeclarations || fn->hasBody())
		{
			this->fn = fn.get();
			doRun(*fn);
		}
	}
}
