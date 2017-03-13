//
// pass_removeundef.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "ast_context.h"
#include "ast_passes.h"

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
			{
				StatementList::erase(exprUser);
				exprUser->dropAllReferences();
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
