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
#include "pass_variablereferences.h"

#include <iostream>

using namespace llvm;
using namespace std;

namespace
{
	void dumpNoPrefix(raw_ostream& os, VariableReferences::use_iterator use)
	{
		os << use->owner.indexBegin << " <" << static_cast<const void*>(use->location) << ">: ";
		use->owner.statement->printShort(os);
	}
	
	void dump(raw_ostream& os, VariableReferences::use_iterator use)
	{
		os << '\t' << "Use ";
		dumpNoPrefix(os, use);
		os << '\n';
	}
	
	void dump(raw_ostream& os, AstVariableReferences& refs, VariableReferences::def_iterator def)
	{
		os << '\t' << "Def " << def->owner.indexBegin << ": ";
		def->owner.statement->printShort(os);
		os << '\n';
		
		for (auto pair : refs.usesReachedByDef(def))
		{
			if (pair.second == ReachStrength::Dominating)
			{
				os << "\t\tDominates ";
				dumpNoPrefix(os, pair.first);
				os << '\n';
			}
		}
	}
	
	void referencesInExpression(llvm::SmallVector<VariableReferences*, 4>& refList, AstVariableReferences& references, Expression* expr)
	{
		if (auto refs = references.getReferences(expr))
		{
			refList.push_back(refs);
		}
		
		if (auto unary = dyn_cast<UnaryOperatorExpression>(expr))
		{
			referencesInExpression(refList, references, unary->operand);
		}
		else if (auto castExpression = dyn_cast<CastExpression>(expr))
		{
			referencesInExpression(refList, references, castExpression->casted);
		}
		else if (auto nary = dyn_cast<NAryOperatorExpression>(expr))
		{
			for (auto subExpr : nary->operands)
			{
				referencesInExpression(refList, references, subExpr);
			}
		}
		else if (auto call = dyn_cast<CallExpression>(expr))
		{
			for (auto subExpr : call->parameters)
			{
				referencesInExpression(refList, references, subExpr);
			}
		}
		else if (auto agg = dyn_cast<AggregateExpression>(expr))
		{
			for (auto subExpr : agg->values)
			{
				referencesInExpression(refList, references, subExpr);
			}
		}
	}
	
	SmallVector<StatementInfo*, 4> pathLeadingToStatement(StatementInfo* statement)
	{
		SmallVector<StatementInfo*, 4> path;
		StatementInfo* current = statement;
		while (current != nullptr)
		{
			path.push_back(current);
			current = current->parent;
		}
		reverse(path.begin(), path.end());
		return path;
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
		
		void visitAggregate(AggregateExpression* agg) override
		{
			if (existingExpressions.count(agg) == 0)
			{
				ExpressionCloneVisitor::visitAggregate(agg);
			}
			else
			{
				result = agg;
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

void AstVariableReferences::visitSubexpression(unordered_set<Expression*>& setExpressions, StatementInfo &owner, Expression* expr)
{
	if (auto unary = dyn_cast<UnaryOperatorExpression>(expr))
	{
		visitUse(setExpressions, owner, addressOf(unary->operand));
	}
	else if (auto nary = dyn_cast<NAryOperatorExpression>(expr))
	{
		for (auto& subExpression : nary->operands)
		{
			visitUse(setExpressions, owner, addressOf(subExpression));
		}
	}
	else if (auto ternary = dyn_cast<TernaryExpression>(expr))
	{
		visitUse(setExpressions, owner, addressOf(ternary->condition));
		visitUse(setExpressions, owner, addressOf(ternary->ifTrue));
		visitUse(setExpressions, owner, addressOf(ternary->ifFalse));
	}
	else if (isa<NumericExpression>(expr) || isa<TokenExpression>(expr))
	{
		// terminals; nothing to do
		// (the token case could have been handled already by the isDef or iterator case)
	}
	else if (auto call = dyn_cast<CallExpression>(expr))
	{
		// TODO: Call expression should check for pointer arguments
		visitUse(setExpressions, owner, addressOf(call->callee));
		for (auto& param : call->parameters)
		{
			visitUse(setExpressions, owner, addressOf(param));
		}
	}
	else if (auto cast = dyn_cast<CastExpression>(expr))
	{
		// no need to visit type since it can't be a declared variable
		visitUse(setExpressions, owner, addressOf(cast->casted));
	}
	else if (auto agg = dyn_cast<AggregateExpression>(expr))
	{
		for (auto& param : agg->values)
		{
			visitUse(setExpressions, owner, addressOf(param));
		}
	}
	else
	{
		llvm_unreachable("unhandled expression type");
	}
}

void AstVariableReferences::visitUse(unordered_set<Expression*>& setExpressions, StatementInfo& owner, Expression** expressionLocation)
{
	auto expr = *expressionLocation;
	if (expr == nullptr)
	{
		return;
	}
	
	auto iter = references.find(expr);
	if (iter != references.end())
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
	
	visitSubexpression(setExpressions, owner, expr);
}

void AstVariableReferences::visitDef(unordered_set<Expression*>& setExpressions, StatementInfo& owner, Expression* definedValue, Expression** value)
{
	// Don't count setting def to __undefined as a def.
	if (*value != TokenExpression::undefExpression)
	{
		auto iter = references.find(definedValue);
		if (iter == references.end())
		{
			VariableReferences uses(definedValue);
			iter = references.insert({definedValue, move(uses)}).first;
			declarationOrder.push_back(definedValue);
		}
		
		VariableReferences& varUses = iter->second;
		bool exists = any_of(varUses.defs.begin(), varUses.defs.end(), [&](VariableDef& def)
		{
			return *def.definitionValue == definedValue;
		});
		
		if (!exists)
		{
			varUses.defs.emplace_back(owner, definedValue, value);
		}
	}
	
	visitSubexpression(setExpressions, owner, definedValue);
}

void AstVariableReferences::visit(unordered_set<Expression*>& setExpressions, StatementInfo* parent, Statement *statement)
{
	if (statement == nullptr)
	{
		return;
	}
	
	statementInfo.emplace_back(statement, statementInfo.size(), parent);
	StatementInfo& thisInfo = statementInfo.back();
	
	unordered_set<Expression*> assignments;
	if (auto ifElse = dyn_cast<IfElseNode>(statement))
	{
		visit(assignments, &thisInfo, &ifElse->conditionExpression);
		
		unordered_set<Expression*> ifSet, elseSet;
		visit(ifSet, &thisInfo, ifElse->ifBody);
		visit(elseSet, &thisInfo, ifElse->elseBody);
		for (auto expr : ifSet)
		{
			if (elseSet.count(expr) != 0)
			{
				assignments.insert(expr);
			}
		}
	}
	else if (auto loop = dyn_cast<LoopNode>(statement))
	{
		visitUse(setExpressions, thisInfo, addressOf(loop->condition));
		
		unordered_set<Expression*> bodySet;
		if (loop->position == LoopNode::PreTested)
		{
			visit(bodySet, &thisInfo, &loop->conditionExpression);
		}
		
		visit(bodySet, &thisInfo, loop->loopBody);
		
		if (loop->position == LoopNode::PostTested)
		{
			visit(bodySet, &thisInfo, &loop->conditionExpression);
			assignments = move(bodySet);
		}
	}
	else if (auto seq = dyn_cast<SequenceNode>(statement))
	{
		for (auto stmt : seq->statements)
		{
			visit(assignments, &thisInfo, stmt);
		}
	}
	else if (auto assignment = dyn_cast<AssignmentNode>(statement))
	{
		visitDef(assignments, thisInfo, assignment->left, addressOf(assignment->right));
		visitUse(assignments, thisInfo, addressOf(assignment->right));
	}
	else if (auto keyword = dyn_cast<KeywordNode>(statement))
	{
		visitUse(assignments, thisInfo, &keyword->operand);
	}
	else if (auto expr = dyn_cast<ExpressionNode>(statement))
	{
		visitUse(assignments, thisInfo, addressOf(expr->expression));
	}
	else
	{
		llvm_unreachable("unhandled AST node type");
	}
	
	thisInfo.indexEnd = statementInfo.size();
	for (auto expr : assignments)
	{
		setExpressions.insert(expr);
		dominatingDefs[expr].insert(thisInfo.indexBegin);
	}
}

void AstVariableReferences::doRun(FunctionNode &fn)
{
	declarationOrder.clear();
	statementInfo.clear();
	references.clear();
	dominatingDefs.clear();
	
	for (Argument& arg : fn.getFunction().getArgumentList())
	{
		auto token = cast<TokenExpression>(fn.valueFor(arg));
		VariableReferences uses(token);
		references.insert({token, move(uses)});
		declarationOrder.push_back(token);
	}
	
	unordered_set<Expression*> setExpressions;
	visit(setExpressions, nullptr, fn.body);
}

const char* AstVariableReferences::getName() const
{
	return "Analyze variable uses";
}

VariableReferences& AstVariableReferences::getReferences(iterator iter)
{
	return references.at(*iter);
}

VariableReferences& AstVariableReferences::getReferences(reverse_iterator iter)
{
	return references.at(*iter);
}

VariableReferences* AstVariableReferences::getReferences(Expression* expr)
{
	auto iter = references.find(expr);
	if (iter != references.end())
	{
		return &iter->second;
	}
	return nullptr;
}

llvm::SmallVector<VariableReferences*, 4> AstVariableReferences::referencesInExpression(Expression *expr)
{
	llvm::SmallVector<VariableReferences*, 4> result;
	::referencesInExpression(result, *this, expr);
	return result;
}

SmallVector<ReachedUse, 4> AstVariableReferences::usesReachedByDef(VariableReferences::def_iterator def)
{
	SmallVector<ReachedUse, 4> result;
	VariableReferences& refs = *getReferences(def->definedExpression);
	auto pathToDef = pathLeadingToStatement(&def->owner);
	const auto& dominatingDefsOfExpression = dominatingDefs[def->definedExpression];
	
	typedef decltype(pathToDef)::reverse_iterator path_reverse_iterator;
	
	auto usesEnd = refs.uses.end();
	for (auto useIter = refs.uses.begin(); useIter != usesEnd; ++useIter)
	{
		auto pathToUse = pathLeadingToStatement(&useIter->owner);
		auto commonSequenceEnd = mismatch(pathToDef.begin(), pathToDef.end(), pathToUse.begin());
		
		ReachStrength strength = ReachStrength::Dominating;
		
		// Is this def after the use?
		if (useIter->owner.indexBegin < def->owner.indexBegin)
		{
			// First off, this can't be a dominating use because the use happens before the def.
			strength = ReachStrength::Reaching;
			
			// If so, it can only reach if both are part of a common loop and there is no dominating
			// def between the start of the loop and the use.
			bool reached = true;
			auto end = pathToDef.rend();
			auto domHigh = dominatingDefsOfExpression.upper_bound(useIter->owner.indexBegin);
			for (auto iter = path_reverse_iterator(commonSequenceEnd.first); iter != end; ++iter)
			{
				StatementInfo* info = *iter;
				if (isa<LoopNode>(info->statement))
				{
					auto domLow = dominatingDefsOfExpression.lower_bound(info->indexBegin);
					if (domLow != domHigh)
					{
						reached = false;
						break;
					}
				}
			}
			
			if (!reached)
			{
				// Def doesn't reach.
				continue;
			}
		}
		
		// Decrease strength to "Reaching" if definition doesn't dominate use.
		if (strength == ReachStrength::Dominating)
		{
			auto defCommonStart = path_reverse_iterator(commonSequenceEnd.first);
			for (auto defIter = pathToDef.rbegin(); defIter != defCommonStart; ++defIter)
			{
				StatementInfo* info = *defIter;
				if (isa<IfElseNode>(info->statement))
				{
					strength = ReachStrength::Reaching;
					break;
				}
				if (auto loop = dyn_cast<LoopNode>(info->statement))
				if (loop->position == LoopNode::PreTested)
				{
					strength = ReachStrength::Reaching;
					break;
				}
			}
		}
		
		// If there's a dominating def on the way to the use, then the definition cannot reach.
		// If there are reaching defs, then set strength to reaching instead of dominating.
		auto defEnd = refs.defs.end();
		auto defIter = def;
		bool dominated = false;
		for (++defIter; defIter != defEnd; ++defIter)
		{
			if (defIter->owner.indexBegin > useIter->owner.indexBegin)
			{
				break;
			}
			
			auto pathToOtherDef = pathLeadingToStatement(&defIter->owner);
			auto defStatementIter = mismatch(pathToOtherDef.begin(), pathToOtherDef.end(), pathToDef.begin()).first;
			assert(defStatementIter != pathToOtherDef.end());
			
			size_t statementIndex = (*defStatementIter)->indexBegin;
			bool isDominatingDef = dominatingDefsOfExpression.count(statementIndex) != 0;
			if (isDominatingDef)
			{
				dominated = true;
				break;
			}
			else
			{
				strength = ReachStrength::Reaching;
			}
		}
		
		// If the def is not dominated, then we have a conclusive result that should be
		// added to the output.
		if (!dominated)
		{
			// Check if the use is part of a loop that the def isn't part of.
			// This check is only useful if we still think that we have a dominating use on our hands.
			if (strength == ReachStrength::Dominating)
			{
				auto firstLoopIter = find_if(commonSequenceEnd.second, pathToUse.end(), [&](StatementInfo* info)
				{
					return isa<LoopNode>(info->statement);
				});
				
				// If it is, then check if there's any def within that loop.
				if (firstLoopIter != pathToUse.end())
				{
					StatementInfo* info = *firstLoopIter;
					auto otherDefIter = find_if(defIter, defEnd, [&](VariableDef& def)
					{
						return def.owner.indexBegin < info->indexEnd;
					});
					
					if (otherDefIter != defEnd)
					{
						strength = ReachStrength::Reaching;
						break;
					}
				}
			}
			
			result.push_back({useIter, strength});
		}
	}
	
	return result;
}

void AstVariableReferences::replaceUseWith(VariableReferences::use_iterator iter, Expression* replacement)
{
	assert(replacement != nullptr);
	VariableReferences& uses = *getReferences(*iter->location);
	Expression* cloned = CloneExceptTerminals::clone(pool(), references, replacement);
	
	*iter->location = cloned;
	unordered_set<Expression*> setExpressions;
	visitUse(setExpressions, iter->owner, iter->location);
	
	uses.uses.erase(iter);
}

VariableReferences::def_iterator AstVariableReferences::removeDef(VariableReferences::def_iterator defIter)
{
	// Remove references to every subexpression
	for (auto refs : referencesInExpression(*defIter->definitionValue))
	{
		auto useIter = refs->uses.begin();
		auto useEnd = refs->uses.end();
		while (true)
		{
			useIter = find_if(useIter, useEnd, [&](VariableUse& use)
			{
				return &use.owner == &defIter->owner;
			});
			
			if (useIter == useEnd)
			{
				break;
			}
			
			useIter = refs->uses.erase(useIter);
		}
	}
	
	*defIter->definitionValue = TokenExpression::undefExpression;
	
	VariableReferences& refs = *getReferences(defIter->definedExpression);
	return refs.defs.erase(defIter);
}

void AstVariableReferences::dump() const
{
	raw_os_ostream rerr(cerr);
	for (auto expression : declarationOrder)
	{
		auto& varUses = const_cast<VariableReferences&>(references.at(expression));
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
				::dump(rerr, const_cast<AstVariableReferences&>(*this), defIter);
				++defIter;
			}
			else
			{
				::dump(rerr, useIter);
				++useIter;
			}
		}
		rerr << '\n';
	}
}
