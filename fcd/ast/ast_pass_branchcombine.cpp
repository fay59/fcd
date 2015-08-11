//
// ast_pass_branchcombine.cpp
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

#include "ast_pass_branchcombine.h"

using namespace llvm;

SequenceNode* AstBranchCombine::asSequence(Statement* statement)
{
	if (auto seq = dyn_cast<SequenceNode>(statement))
	{
		return seq;
	}
	auto seq = pool().allocate<SequenceNode>(pool());
	seq->statements.push_back(statement);
	return seq;
}

void AstBranchCombine::maybeMergeNestedIf(IfElseNode* root)
{
	if (auto childIfElse = dyn_cast<IfElseNode>(root->ifBody))
	{
		if (root->elseBody == nullptr && childIfElse->elseBody == nullptr)
		{
			root->condition = append(NAryOperatorExpression::ShortCircuitAnd, root->condition, childIfElse->condition);
			root->ifBody = childIfElse->ifBody;
		}
	}
	else
	{
		auto sequence = asSequence(root->ifBody);
		combineBranches(sequence);
	}
	
	if (root->elseBody != nullptr)
	{
		auto sequence = asSequence(root->elseBody);
		combineBranches(sequence);
	}
}

void AstBranchCombine::combineBranches(SequenceNode *simplified, Statement *stmt)
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
				maybeMergeNestedIf(lastIfElse);
				return;
			}
			else
			{
				Expression* negated = negate(thisIfElse->condition);
				if (lastIfElse->condition->isReferenceEqual(negated))
				{
					lastIfElse->ifBody = append(lastIfElse->ifBody, thisIfElse->elseBody);
					lastIfElse->elseBody = append(lastIfElse->elseBody, thisIfElse->ifBody);
					maybeMergeNestedIf(lastIfElse);
					return;
				}
			}
		}
		
		// If it wasn't merged, simplify the current if-else node and insert it.
		maybeMergeNestedIf(thisIfElse);
		simplified->statements.push_back(thisIfElse);
	}
	else
	{
		if (auto loop = dyn_cast<LoopNode>(stmt))
		{
			auto body = asSequence(loop->loopBody);
			loop->loopBody = combineBranches(body);
		}
		else if (auto sequence = dyn_cast<SequenceNode>(stmt))
		{
			stmt = combineBranches(sequence);
		}
		simplified->statements.push_back(stmt);
	}
}

Statement* AstBranchCombine::combineBranches(SequenceNode* statement)
{
	auto simplified = pool().allocate<SequenceNode>(pool());
	for (Statement* stmt : statement->statements)
	{
		combineBranches(simplified, stmt);
	}
	return simplified;
}

const char* AstBranchCombine::getName() const
{
	return "Combine Branches";
}

void AstBranchCombine::doRun(FunctionNode& fn)
{
	auto sequence = asSequence(fn.body);
	fn.body = combineBranches(sequence);
}
