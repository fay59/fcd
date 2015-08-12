//
// pass_variableuses.cpp
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

#include "pass_variableuses.h"

#include <iostream>

using namespace llvm;
using namespace std;

namespace
{
	void dump(raw_ostream& os, const VariableUse& use, const std::string& type)
	{
		os << '\t' << type << ' ' << use.index << " <" << static_cast<const void*>(use.location) << ">: ";
		use.owner->printShort(os);
		os << '\n';
	}
}

VariableUses::VariableUses(Expression* expr)
: expression(expr)
{
}

bool VariableUses::usedBeforeDefined() const
{
	if (uses.size() == 0)
	{
		return false;
	}
	
	if (defs.size() == 0)
	{
		return true;
	}
	
	return uses.front().index < defs.front().index;
}

void AstVariableUses::visit(Statement* owner, Expression** expressionLocation, bool isDef)
{
	auto expr = *expressionLocation;
	if (expr == nullptr)
	{
		assert(!isDef);
		return;
	}
	
	if (!isDef)
	{
		auto iter = declarationUses.find(expr);
		if (iter != declarationUses.end())
		{
			VariableUses& varUses = iter->second;
			varUses.uses.emplace_back(owner, expressionLocation, index);
			++index;
			return;
		}
	}
	else
	{
		auto iter = declarationUses.find(expr);
		if (iter == declarationUses.end())
		{
			VariableUses uses(expr);
			iter = declarationUses.insert({expr, move(uses)}).first;
			declarationOrder.push_back(expr);
		}
		VariableUses& varUses = iter->second;
		varUses.defs.emplace_back(owner, expressionLocation, index);
		++index;
	}
	
	if (auto unary = dyn_cast<UnaryOperatorExpression>(expr))
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
	else if (isa<NumericExpression>(expr) || isa<TokenExpression>(expr))
	{
		// terminals; nothing to do
		// (the token case could have been handled already by the isDef or iterator case)
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
		size_t startIndex = index++;
		visit(loop, addressOf(loop->condition));
		visit(loop->loopBody);
		size_t endIndex = index++;
		
		loopRanges.insert({endIndex, startIndex});
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
	index = 0;
	declarationOrder.clear();
	declarationUses.clear();
	for (Argument& arg : fn.getFunction().getArgumentList())
	{
		auto token = cast<TokenExpression>(fn.valueFor(arg));
		VariableUses uses(token);
		declarationUses.insert({token, move(uses)});
		declarationOrder.push_back(token);
	}
	
	visit(fn.body);
	dump();
}

const char* AstVariableUses::getName() const
{
	return "Analyze variable uses";
}

VariableUses& AstVariableUses::getUseInfo(iterator iter)
{
	return declarationUses.at(*iter);
}

VariableUses* AstVariableUses::getUseInfo(Expression* expr)
{
	auto iter = declarationUses.find(expr);
	if (iter != declarationUses.end())
	{
		return &iter->second;
	}
	return nullptr;
}

size_t AstVariableUses::innermostLoopIndexOfUse(const VariableUse &use) const
{
	auto iter = loopRanges.upper_bound(use.index);
	if (iter != loopRanges.end())
	{
		const auto min = loopRanges.begin();
		while (iter != min)
		{
			if (iter->first > use.index && iter->second < use.index)
			{
				return iter->second;
			}
			--iter;
		}
		
		if (iter->first > use.index && iter->second < use.index)
		{
			return iter->second;
		}
	}
	
	return MaxIndex;
}

void AstVariableUses::replaceUseWith(VariableUses& use, VariableUses::iterator iter, Expression* replacement)
{
	llvm_unreachable("implement me");
}

std::pair<VariableUses::iterator, VariableUses::iterator> AstVariableUses::usesReachedByDef(VariableUses& use, VariableUses::iterator iter) const
{
	llvm_unreachable("implement me");
}

std::pair<VariableUses::iterator, VariableUses::iterator> AstVariableUses::defsReachingUse(VariableUses& use, VariableUses::iterator iter) const
{
	llvm_unreachable("implement me");
}

void AstVariableUses::dump() const
{
	raw_os_ostream rerr(cerr);
	for (auto expression : declarationOrder)
	{
		const auto& varUses = declarationUses.at(expression);
		expression->print(rerr);
		rerr << ": " << varUses.defs.size() << " defs, " << varUses.uses.size() << " uses\n";
		
		auto useIter = varUses.uses.begin();
		auto defIter = varUses.defs.begin();
		const auto useEnd = varUses.uses.end();
		const auto defEnd = varUses.defs.end();
		while (useIter != useEnd || defIter != defEnd)
		{
			if (useIter == useEnd || (defIter != defEnd && defIter->index < useIter->index))
			{
				::dump(rerr, *defIter, "Def");
				++defIter;
			}
			else
			{
				::dump(rerr, *useIter, "Use");
				++useIter;
			}
		}
		rerr << '\n';
	}
}
