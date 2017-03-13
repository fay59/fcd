//
// pass_print.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "pass_print.h"

using namespace llvm;
using namespace std;

void AstPrint::doRun(deque<std::unique_ptr<FunctionNode>> &functions)
{
	for (const auto& file : includes)
	{
		output << "#include \"" << file << "\"\n";
	}
	
	if (includes.size() > 0)
	{
		output << '\n';
	}
	
	for (unique_ptr<FunctionNode>& fn : functions)
	{
		if (!fn->getBody().empty())
		{
			fn->print(output);
		}
	}
}

const char* AstPrint::getName() const
{
	return "Print AST";
}
