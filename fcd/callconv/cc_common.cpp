//
// cc_common.cpp
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

#include "cc_common.h"

using namespace llvm;
using namespace std;

vector<const TargetRegisterInfo*> ipaFindUsedReturns(ParameterRegistry& registry, Function& function, const vector<const TargetRegisterInfo*>& usedReturns)
{
	TargetInfo& targetInfo = registry.getAnalysis<TargetInfo>();
	vector<const TargetRegisterInfo*> result;
	for (auto& use : function.uses())
	{
		if (auto call = dyn_cast<CallInst>(use.getUser()))
		{
			auto parentFunction = call->getParent()->getParent();
			if (parentFunction == &function)
			{
				// This isn't impossible to compute, just somewhat inconvenient.
				continue;
			}
			
			Argument* parentArgs = parentFunction->arg_begin();
			auto pointerType = dyn_cast<PointerType>(parentArgs->getType());
			assert(pointerType != nullptr && pointerType->getTypeAtIndex(int(0))->getStructName() == "struct.x86_regs");
			
			MemorySSA& mssa = *registry.getMemorySSA(*parentFunction);
			MemoryAccess* access = mssa.getMemoryAccess(call);
			for (auto user : access->users())
			{
				if (auto load = dyn_cast<LoadInst>(user->getMemoryInst()))
				if (auto address = dyn_cast<GetElementPtrInst>(load->getPointerOperand()))
				if (address->getPointerOperand() == parentArgs)
				{
					const TargetRegisterInfo* registerInfo = targetInfo.registerInfo(*address);
					auto iter = find(usedReturns.begin(), usedReturns.end(), registerInfo);
					if (iter != usedReturns.end())
					{
						// return value!
						result.push_back(registerInfo);
					}
				}
			}
		}
	}
	return result;
}