//
// ast_pass_variableuses.cpp
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

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include "ast_pass_variableuses.h"

#include <iostream>

using namespace llvm;
using namespace std;

VariableUses::VariableUses(FunctionNode::declaration_iterator iter)
: declaration(iter)
{
}

TokenExpression* VariableUses::type()
{
	DeclarationNode* decl = *declaration;
	return decl->type;
}

TokenExpression* VariableUses::identifier()
{
	DeclarationNode* decl = *declaration;
	return decl->name;
}

void AstVariableUses::visit(Statement* owner, Expression** expressionLocation, bool isDef)
{
	auto expr = *expressionLocation;
	if (expr == nullptr)
	{
		return;
	}
	
	if (auto token = dyn_cast<TokenExpression>(expr))
	{
		auto iter = declarationUses.find(token);
		if (iter != declarationUses.end())
		{
			VariableUses& varUses = iter->second;
			(isDef ? varUses.defs : varUses.uses).emplace_back(owner, expressionLocation);
		}
	}
	else if (auto unary = dyn_cast<UnaryOperatorExpression>(expr))
	{
		visit(owner, addressOf(unary->operand));
	}
	else if (auto nary = dyn_cast<NAryOperatorExpression>(expr))
	{
		for (auto& subExpression : nary->operands)
		{
			visit(owner, addressOf(subExpression));
		}
	}
	else if (auto ternary = dyn_cast<TernaryExpression>(expr))
	{
		visit(owner, addressOf(ternary->condition));
		visit(owner, addressOf(ternary->ifTrue));
		visit(owner, addressOf(ternary->ifFalse));
	}
	else if (isa<NumericExpression>(expr))
	{
		// nothing to do
	}
	else if (auto call = dyn_cast<CallExpression>(expr))
	{
		visit(owner, addressOf(call->callee));
		for (auto& param : call->parameters)
		{
			visit(owner, addressOf(param));
		}
	}
	else if (auto cast = dyn_cast<CastExpression>(expr))
	{
		// no need to visit type since it can't be a declared variable
		visit(owner, addressOf(cast->casted));
	}
	else
	{
		llvm_unreachable("unhandled expression type");
	}
}

void AstVariableUses::visit(Statement *statement)
{
	if (statement == nullptr)
	{
		return;
	}
	
	if (auto seq = dyn_cast<SequenceNode>(statement))
	{
		for (auto stmt : seq->statements)
		{
			visit(stmt);
		}
	}
	else if (auto ifElse = dyn_cast<IfElseNode>(statement))
	{
		visit(ifElse, addressOf(ifElse->condition));
		visit(ifElse->ifBody);
		visit(ifElse->elseBody);
	}
	else if (auto loop = dyn_cast<LoopNode>(statement))
	{
		visit(loop, addressOf(loop->condition));
		visit(loop->loopBody);
	}
	else if (auto keyword = dyn_cast<KeywordNode>(statement))
	{
		visit(keyword, &keyword->operand);
	}
	else if (auto expr = dyn_cast<ExpressionNode>(statement))
	{
		visit(expr, addressOf(expr->expression));
	}
	else if (auto assignment = dyn_cast<AssignmentNode>(statement))
	{
		visit(assignment, addressOf(assignment->left), true);
		visit(assignment, addressOf(assignment->right));
	}
	else
	{
		llvm_unreachable("unhandled AST node type");
	}
}

void AstVariableUses::doRun(FunctionNode &fn)
{
	declarationUses.clear();
	for (auto iter = fn.decls_begin(); iter != fn.decls_end(); iter++)
	{
		VariableUses uses(iter);
		auto id = uses.identifier();
		declarationUses.insert({id, move(uses)});
	}
	
	visit(fn.body);
	dump();
}

const char* AstVariableUses::getName() const
{
	return "Variable uses";
}

void AstVariableUses::dump() const
{
	raw_os_ostream rerr(cerr);
	for (const auto& pair : declarationUses)
	{
		auto token = pair.first;
		const auto& varUses = pair.second;
		rerr << token->token << ": " << varUses.defs.size() << " defs, " << varUses.uses.size() << " uses\n";
		for (const auto& def : varUses.defs)
		{
			rerr << "\tOwner: ";
			def.owner->print(rerr);
			rerr << "\tLocation: <" << static_cast<const void*>(def.location) << ">\n";
		}
		rerr << '\n';
		for (const auto& use : varUses.uses)
		{
			rerr << "\tOwner: <" << static_cast<const void*>(use.owner) << ">\n";
			rerr << "\tLocation: <" << static_cast<const void*>(use.location) << ">\n";
		}
		rerr << '\n';
	}
}
