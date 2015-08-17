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
	void dump(raw_ostream& os, const VariableUse& use)
	{
		os << '\t' << "Use " << use.owner.indexBegin << " <" << static_cast<const void*>(use.location) << ">: ";
		use.owner.statement->printShort(os);
		os << '\n';
	}
	
	void dump(raw_ostream& os, const VariableDef& def)
	{
		os << '\t' << "Def " << def.owner.indexBegin << ": ";
		def.owner.statement->printShort(os);
		os << '\n';
	}
	
	// Alternate clone visitor that only copies values that are not assignable.
	class CloneExceptTerminals : public ExpressionCloneVisitor
	{
		const unordered_map<Expression*, VariableReferences>& existingExpressions;
		
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
		CloneExceptTerminals(DumbAllocator& pool, const unordered_map<Expression*, VariableReferences>& terminals)
		: ExpressionCloneVisitor(pool), existingExpressions(terminals)
		{
		}
		
		static Expression* clone(DumbAllocator& pool, const unordered_map<Expression*, VariableReferences>& terminals, Expression* expression)
		{
			return CloneExceptTerminals(pool, terminals).ExpressionCloneVisitor::clone(expression);
		}
	};
}

VariableReferences::VariableReferences(Expression* expr)
: expression(expr)
{
}

void AstVariableUses::visitSubexpression(StatementInfo &owner, Expression* expr)
{
	if (auto unary = dyn_cast<UnaryOperatorExpression>(expr))
	{
		visitUse(owner, addressOf(unary->operand));
	}
	else if (auto nary = dyn_cast<NAryOperatorExpression>(expr))
	{
		for (auto& subExpression : nary->operands)
		{
			visitUse(owner, addressOf(subExpression));
		}
	}
	else if (auto ternary = dyn_cast<TernaryExpression>(expr))
	{
		visitUse(owner, addressOf(ternary->condition));
		visitUse(owner, addressOf(ternary->ifTrue));
		visitUse(owner, addressOf(ternary->ifFalse));
	}
	else if (isa<NumericExpression>(expr) || isa<TokenExpression>(expr))
	{
		// terminals; nothing to do
		// (the token case could have been handled already by the isDef or iterator case)
	}
	else if (auto call = dyn_cast<CallExpression>(expr))
	{
#warning TODO: Call expression should check for pointer arguments
		visitUse(owner, addressOf(call->callee));
		for (auto& param : call->parameters)
		{
			visitUse(owner, addressOf(param));
		}
	}
	else if (auto cast = dyn_cast<CastExpression>(expr))
	{
		// no need to visit type since it can't be a declared variable
		visitUse(owner, addressOf(cast->casted));
	}
	else
	{
		llvm_unreachable("unhandled expression type");
	}
}

void AstVariableUses::visitUse(StatementInfo& owner, Expression** expressionLocation)
{
	auto expr = *expressionLocation;
	if (expr == nullptr)
	{
		return;
	}
	
	auto iter = declarationUses.find(expr);
	if (iter != declarationUses.end())
	{
		VariableReferences& varUses = iter->second;
		bool exists = any_of(varUses.uses.begin(), varUses.uses.end(), [&](VariableUse& use)
		{
			return use.location == expressionLocation;
		});
		if (!exists)
		{
			varUses.uses.emplace_back(owner, expressionLocation);
		}
		return;
	}
	
	visitSubexpression(owner, expr);
}

void AstVariableUses::visitDef(StatementInfo& owner, Expression* definedValue, Expression* value)
{
	auto iter = declarationUses.find(definedValue);
	if (iter == declarationUses.end())
	{
		VariableReferences uses(definedValue);
		iter = declarationUses.insert({definedValue, move(uses)}).first;
		declarationOrder.push_back(definedValue);
	}
	
	VariableReferences& varUses = iter->second;
	bool exists = any_of(varUses.defs.begin(), varUses.defs.end(), [&](VariableDef& def)
	{
		return def.definitionValue == definedValue;
	});
	
	if (!exists)
	{
		varUses.defs.emplace_back(owner, definedValue, value);
	}
	
	visitSubexpression(owner, definedValue);
}

void AstVariableUses::visit(StatementInfo* parent, Statement *statement)
{
	if (statement == nullptr)
	{
		return;
	}
	
	statementInfo.emplace_back(statement, statementInfo.size(), parent);
	StatementInfo& thisInfo = statementInfo.back();
	
	if (auto seq = dyn_cast<SequenceNode>(statement))
	{
		for (auto stmt : seq->statements)
		{
			visit(&thisInfo, stmt);
		}
	}
	else if (auto ifElse = dyn_cast<IfElseNode>(statement))
	{
		visitUse(thisInfo, addressOf(ifElse->condition));
		visit(&thisInfo, ifElse->ifBody);
		visit(&thisInfo, ifElse->elseBody);
	}
	else if (auto loop = dyn_cast<LoopNode>(statement))
	{
		visitUse(thisInfo, addressOf(loop->condition));
		visit(&thisInfo, loop->loopBody);
	}
	else if (auto keyword = dyn_cast<KeywordNode>(statement))
	{
		visitUse(thisInfo, &keyword->operand);
	}
	else if (auto expr = dyn_cast<ExpressionNode>(statement))
	{
		visitUse(thisInfo, addressOf(expr->expression));
	}
	else if (auto assignment = dyn_cast<AssignmentNode>(statement))
	{
		visitDef(thisInfo, assignment->left, assignment->right);
		visitUse(thisInfo, addressOf(assignment->right));
	}
	else
	{
		llvm_unreachable("unhandled AST node type");
	}
	
	thisInfo.indexEnd = statementInfo.size();
}

void AstVariableUses::doRun(FunctionNode &fn)
{
	declarationOrder.clear();
	declarationUses.clear();
	statementInfo.clear();
	
	for (Argument& arg : fn.getFunction().getArgumentList())
	{
		auto token = cast<TokenExpression>(fn.valueFor(arg));
		VariableReferences uses(token);
		declarationUses.insert({token, move(uses)});
		declarationOrder.push_back(token);
	}
	
	visit(nullptr, fn.body);
	dump();
}

const char* AstVariableUses::getName() const
{
	return "Analyze variable uses";
}

VariableReferences& AstVariableUses::getUseInfo(iterator iter)
{
	return declarationUses.at(*iter);
}

VariableReferences* AstVariableUses::getUseInfo(Expression* expr)
{
	auto iter = declarationUses.find(expr);
	if (iter != declarationUses.end())
	{
		return &iter->second;
	}
	return nullptr;
}

void AstVariableUses::replaceUseWith(VariableReferences::use_iterator iter, Expression* replacement)
{
	VariableReferences& uses = *getUseInfo(*iter->location);
	Expression* cloned = CloneExceptTerminals::clone(pool(), declarationUses, replacement);
	*iter->location = cloned;
	visitUse(iter->owner, iter->location);
	uses.uses.erase(iter);
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
			if (useIter == useEnd || (defIter != defEnd && defIter->owner.indexBegin < useIter->owner.indexBegin))
			{
				::dump(rerr, *defIter);
				++defIter;
			}
			else
			{
				::dump(rerr, *useIter);
				++useIter;
			}
		}
		rerr << '\n';
	}
}
