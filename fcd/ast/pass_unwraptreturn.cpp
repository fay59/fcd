//
// pass_unwraptreturn.cpp
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

#include "pass_unwrapreturn.h"
#include "visitor.h"

#include <set>
#include <string>

using namespace llvm;
using namespace std;

namespace
{
	struct UnwrapReturns : public StatementVisitor
	{
		const set<string>& singleReturns;
		
		UnwrapReturns(const set<string>& singleReturns)
		: singleReturns(singleReturns)
		{
		}
		
		virtual void visitAssignment(AssignmentNode* assignment) override
		{
			if (auto call = dyn_cast<CallExpression>(assignment->right))
			if (auto token = dyn_cast<TokenExpression>(call->callee))
			if (singleReturns.count(token->token.ptr) == 1)
			if (auto wrapped = dyn_cast<AggregateExpression>(assignment->left))
			{
				assignment->left = wrapped->values[0];
			}
		}
	};
	
	set<string> identifySingleReturnFunctions(deque<unique_ptr<FunctionNode>>& functions)
	{
		set<string> singleReturnFunctions;
		for (auto& function : functions)
		{
			if (auto structType = dyn_cast<StructType>(&function->getReturnType()))
			if (structType->getNumElements() == 1)
			{
				StringRef name = function->getFunction().getName();
				if (name.size() > 0)
				{
					singleReturnFunctions.insert(name);
				}
			}
		}
		return singleReturnFunctions;
	}
}

void AstUnwrapReturns::doRun(deque<unique_ptr<FunctionNode>>& functions)
{
	set<string> singleReturnFunctions = identifySingleReturnFunctions(functions);
	UnwrapReturns visitor(singleReturnFunctions);
	
	for (auto& function : functions)
	{
		if (singleReturnFunctions.count(function->getFunction().getName()))
		{
			auto& structType = cast<StructType>(function->getReturnType());
			function->setReturnType(*structType.getElementType(0));
		}
		
		if (function->hasBody())
		{
			function->body->visit(visitor);
		}
	}
}

const char* AstUnwrapReturns::getName() const
{
	return "Unwrap return values";
}
