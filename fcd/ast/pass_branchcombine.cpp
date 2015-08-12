//
// pass_branchcombine.cpp
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

#include "pass_branchcombine.h"

using namespace llvm;

Statement* AstBranchCombine::combineBranches(SequenceNode* statement)
{
	auto simplified = pool().allocate<SequenceNode>(pool());
	
	for (Statement* stmt : statement->statements)
	{
		if (auto thisIfElse = dyn_cast<IfElseNode>(stmt))
		{
			if (auto lastNode = simplified->statements.back_or_null())
			if (auto lastIfElse = dyn_cast_or_null<IfElseNode>(*lastNode))
			{
				if (lastIfElse->condition->isReferenceEqual(thisIfElse->condition))
				{
					lastIfElse->ifBody = append(lastIfElse->ifBody, thisIfElse->ifBody);
					lastIfElse->elseBody = append(lastIfElse->elseBody, thisIfElse->elseBody);
					simplified->statements.back() = combineBranches(lastIfElse);
					continue;
				}
				else
				{
					Expression* negated = negate(thisIfElse->condition);
					if (lastIfElse->condition->isReferenceEqual(negated))
					{
						lastIfElse->ifBody = append(lastIfElse->ifBody, thisIfElse->elseBody);
						lastIfElse->elseBody = append(lastIfElse->elseBody, thisIfElse->ifBody);
						simplified->statements.back() = combineBranches(lastIfElse);
						continue;
					}
				}
			}
		}
		
		// If it wasn't combined, try to simplify.
		if (auto statement = combineBranches(stmt))
		{
			simplified->statements.push_back(statement);
		}
	}
	return simplified;
}

Statement* AstBranchCombine::combineBranches(IfElseNode* root)
{
	bool combined = false;
	if (auto childIfElse = dyn_cast<IfElseNode>(root->ifBody))
	{
		if (root->elseBody == nullptr && childIfElse->elseBody == nullptr)
		{
			root->condition = append(NAryOperatorExpression::ShortCircuitAnd, root->condition, childIfElse->condition);
			root->ifBody = childIfElse->ifBody;
			combined = true;
		}
	}
	
	if (!combined)
	{
		root->ifBody = combineBranches(root->ifBody);
	}
	
	if (root->elseBody != nullptr)
	{
		root->elseBody = combineBranches(root->elseBody);
	}
	
	return root;
}

Statement* AstBranchCombine::combineBranches(Statement *statement)
{
	if (auto seq = dyn_cast<SequenceNode>(statement))
	{
		return combineBranches(seq);
	}
	else if (auto ifElse = dyn_cast<IfElseNode>(statement))
	{
		return combineBranches(ifElse);
	}
	else if (auto loop = dyn_cast<LoopNode>(statement))
	{
		loop->loopBody = combineBranches(loop->loopBody);
		return loop;
	}
	else
	{
		return statement;
	}
}

const char* AstBranchCombine::getName() const
{
	return "Combine Branches";
}

void AstBranchCombine::doRun(FunctionNode& fn)
{
	fn.body = combineBranches(fn.body);
}
