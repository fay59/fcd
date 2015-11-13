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

void AstPropagateValues::attemptToPropagateUses(AstVariableReferences& useAnalysis, VariableReferences &uses)
{
	auto defIterator = uses.defs.begin();
	auto defEnd = uses.defs.end();
	while (defIterator != defEnd)
	{
		auto reach = useAnalysis.usesReachedByDef(defIterator);
		// Attempt to expand uses with their definition when:
		// 1- The definition dominates the use;
		// 2- There is only one use of that definition.
		
		bool safeToPropagate = false;
		if (reach.size() == 1)
		{
			if (reach[0].second == ReachStrength::Dominating)
			{
				// Make sure that replacing is safe: is any value in that statement modified
				// between the definition and the use?
				auto minIndex = defIterator->owner.indexBegin;
				auto maxIndex = reach[0].first->owner.indexBegin;
				
				auto refsToSubexpressions = useAnalysis.referencesInExpression(*defIterator->definitionValue);
				safeToPropagate = all_of(refsToSubexpressions.begin(), refsToSubexpressions.end(), [&](const VariableReferences* refs)
				{
					return all_of(refs->defs.begin(), refs->defs.end(), [&](const VariableDef& def)
					{
						auto defIndex = def.owner.indexBegin;
						return defIndex < minIndex || defIndex >= maxIndex;
					});
				});
			}
		}
		
		if (safeToPropagate)
		{
			useAnalysis.replaceUseWith(pool(), reach[0].first, *defIterator->definitionValue);
			defIterator = useAnalysis.removeDef(defIterator);
		}
		else
		{
			++defIterator;
		}
	}
}

void AstPropagateValues::doRun(FunctionNode &fn)
{
	AstVariableReferences& useAnalysis = *useAnalysisPass.getReferences(fn);
	auto end = useAnalysis.rend();
	for (auto iter = useAnalysis.rbegin(); iter != end; ++iter)
	{
		auto& use = useAnalysis.getReferences(iter);
		attemptToPropagateUses(useAnalysis, use);
	}
}

const char* AstPropagateValues::getName() const
{
	return "Propagate values";
}
