//
// ast_pass_propagatevalues.cpp
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

#include "ast_pass_propagatevalues.h"
#include "llvm_warnings.h"

using namespace llvm;
using namespace std;

namespace
{
	bool containsOneElement(const pair<VariableUses::iterator, VariableUses::iterator>& pair)
	{
		auto iter = pair.first;
		++iter;
		return iter == pair.second;
	}
}

void AstPropagateValues::attemptToPropagateUses(VariableUses &uses)
{
	auto nextDef = uses.defs.begin();
	for (auto iter = nextDef; iter != uses.defs.end(); iter = nextDef)
	{
		nextDef++;
		
		if (auto assignment = dyn_cast<AssignmentNode>(iter->owner))
		{
			// If the def has a single use and the use has a single def, replace the use with the right hand of the
			// assignment.
			auto defReach = useAnalysis.usesReachedByDef(uses, iter);
			if (containsOneElement(defReach))
			{
				auto& useIter = defReach.first;
				auto useReach = useAnalysis.defsReachingUse(uses, useIter);
				if (containsOneElement(useReach))
				{
					useAnalysis.replaceUseWith(uses, useIter, assignment->right);
				}
			}
		}
	}
}

AstPropagateValues::AstPropagateValues(AstVariableUses& uses)
: useAnalysis(uses)
{
}

void AstPropagateValues::doRun(FunctionNode &fn)
{
	auto end = useAnalysis.end();
	for (auto iter = useAnalysis.begin(); iter != end; ++iter)
	{
		auto& use = useAnalysis.getUseInfo(iter);
		attemptToPropagateUses(use);
	}
}

const char* AstPropagateValues::getName() const
{
	return "Propagate values";
}
