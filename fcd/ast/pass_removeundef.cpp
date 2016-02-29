//
// pass_removeundef.cpp
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

#include "ast_context.h"
#include "pass_removeundef.h"

using namespace llvm;
using namespace std;

namespace
{
	NAryOperatorExpression* asUndefAssignment(const Expression& undef, ExpressionUse& use)
	{
		if (auto user = dyn_cast<NAryOperatorExpression>(use.getUser()))
		if (user->getType() == NAryOperatorExpression::Assign)
		if (user->getOperand(user->operands_size() - 1) == &undef)
		{
			return user;
		}
		return nullptr;
	}
	
	void removeStatementUses(AstContext& context, Expression& expr)
	{
		for (ExpressionUse& use : expr.uses())
		{
			if (auto exprUser = dyn_cast<ExpressionStatement>(use.getUser()))
			if (auto parent = exprUser->getParent())
			{
				parent->replaceChild(exprUser, context.noop());
			}
		}
	}
}

void AstRemoveUndef::doRun(FunctionNode &fn)
{
	auto& context = fn.getContext();
	auto undef = context.expressionForUndef();
	for (ExpressionUse& use : undef->uses())
	{
		if (auto undefAssignment = asUndefAssignment(*undef, use))
		{
			removeStatementUses(context, *undefAssignment);
		}
	}
}

const char* AstRemoveUndef::getName() const
{
	return "Remove undefined assignments";
}
