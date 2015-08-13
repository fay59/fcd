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

#include "clone.h"
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
	
	// Alternate clone visitor that only copies values that are not assignable.
	class CloneExceptTerminals : public ExpressionCloneVisitor
	{
		const unordered_map<Expression*, VariableUses>& existingExpressions;
		
	protected:
		void visitNumeric(NumericExpression* numeric) override
		{
			result = numeric;
		}
		
		void visitUnary(UnaryOperatorExpression* unary) override
		{
			if (existingExpressions.count(unary) == 0)
			{
				ExpressionCloneVisitor::visitUnary(unary);
			}
			else
			{
				result = unary;
			}
		}
		
		void visitToken(TokenExpression* token) override
		{
			if (existingExpressions.count(token) == 0)
			{
				ExpressionCloneVisitor::visitToken(token);
			}
			else
			{
				result = token;
			}
		}
		
	public:
		CloneExceptTerminals(DumbAllocator& pool, const unordered_map<Expression*, VariableUses>& terminals)
		: ExpressionCloneVisitor(pool), existingExpressions(terminals)
		{
		}
		
		static Expression* clone(DumbAllocator& pool, const unordered_map<Expression*, VariableUses>& terminals, Expression* expression)
		{
			return CloneExceptTerminals(pool, terminals).ExpressionCloneVisitor::clone(expression);
		}
	};
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
	
	// Determine statement index for current statement.
	auto statementIter = statements.find(owner);
	if (statementIter == statements.end())
	{
		statementIter = statements.insert({owner, index++}).first;
	}
	size_t statementIndex = statementIter->second;
	
	if (!isDef)
	{
		auto iter = declarationUses.find(expr);
		if (iter != declarationUses.end())
		{
			VariableUses& varUses = iter->second;
			bool exists = any_of(varUses.uses.begin(), varUses.uses.end(), [&](VariableUse& use)
			{
				return use.location == expressionLocation;
			});
			if (!exists)
			{
				varUses.uses.emplace_back(owner, expressionLocation, statementIndex);
			}
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
		bool exists = any_of(varUses.defs.begin(), varUses.defs.end(), [&](VariableUse& def)
		{
			return def.location == expressionLocation;
		});
		if (!exists)
		{
			varUses.defs.emplace_back(owner, expressionLocation, statementIndex);
		}
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
	index = 0;
	declarationOrder.clear();
	declarationUses.clear();
	statements.clear();
	
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

void AstVariableUses::replaceUseWith(VariableUses::iterator iter, Expression* replacement)
{
	VariableUses& uses = *getUseInfo(*iter->location);
	Expression* cloned = CloneExceptTerminals::clone(pool(), declarationUses, replacement);
	*iter->location = cloned;
	visit(iter->owner);
	uses.uses.erase(iter);
}

std::pair<VariableUses::iterator, VariableUses::iterator> AstVariableUses::usesReachedByDef(VariableUses::iterator iter) const
{
	llvm_unreachable("implement me");
}

std::pair<VariableUses::iterator, VariableUses::iterator> AstVariableUses::defsReachingUse(VariableUses::iterator iter) const
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
