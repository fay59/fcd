//
// pass_propagatevalues.cpp
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

#include "pass_propagatevalues.h"

using namespace llvm;
using namespace std;

namespace
{
	void referencesOfSubexpression(deque<VariableReferences*>& refList, AstVariableReferences& references, Expression* expr)
	{
		if (auto refs = references.getReferences(expr))
		{
			refList.push_back(refs);
		}
		
		if (auto unary = dyn_cast<UnaryOperatorExpression>(expr))
		{
			referencesOfSubexpression(refList, references, unary->operand);
		}
		else if (auto nary = dyn_cast<NAryOperatorExpression>(expr))
		{
			for (auto subExpr : nary->operands)
			{
				referencesOfSubexpression(refList, references, subExpr);
			}
		}
		else if (auto call = dyn_cast<CallExpression>(expr))
		{
			for (auto subExpr : call->parameters)
			{
				referencesOfSubexpression(refList, references, subExpr);
			}
		}
	}
	
	deque<VariableReferences*> referencesOfSubexpressions(AstVariableReferences& references, Expression* expr)
	{
		deque<VariableReferences*> result;
		referencesOfSubexpression(result, references, expr);
		return result;
	}
}

void AstPropagateValues::attemptToPropagateUses(VariableReferences &uses)
{
	for (auto defIterator = uses.defs.begin(); defIterator != uses.defs.end(); ++defIterator)
	{
		auto reach = useAnalysis.usesReachedByDef(defIterator);
		// Attempt to expand uses with their definition when:
		// 1- The definition dominates the use;
		// 2- There is only one use of that definition.
		if (reach.size() == 1 && reach[0].second == ReachStrength::Dominating)
		{
			auto useIterator = reach[0].first;
			// Make sure that replacing is safe: is any value in that statement modified
			// between the definition and the use?
			auto minIndex = defIterator->owner.indexBegin;
			auto maxIndex = useIterator->owner.indexBegin;
			
			auto refsToSubexpressions = referencesOfSubexpressions(useAnalysis, defIterator->definitionValue);
			bool safeToPropagate = all_of(refsToSubexpressions.begin(), refsToSubexpressions.end(), [&](const VariableReferences* refs)
			{
				return all_of(refs->defs.begin(), refs->defs.end(), [&](const VariableDef& def)
				{
					auto defIndex = def.owner.indexBegin;
					return defIndex < minIndex || defIndex >= maxIndex;
				});
			});
			
			if (safeToPropagate)
			{
				useAnalysis.replaceUseWith(useIterator, defIterator->definitionValue);
			}
		}
	}
}

AstPropagateValues::AstPropagateValues(AstVariableReferences& uses)
: useAnalysis(uses)
{
}

void AstPropagateValues::doRun(FunctionNode &fn)
{
	auto end = useAnalysis.end();
	for (auto iter = useAnalysis.begin(); iter != end; ++iter)
	{
		auto& use = useAnalysis.getReferences(iter);
		attemptToPropagateUses(use);
	}
}

const char* AstPropagateValues::getName() const
{
	return "Propagate values";
}
