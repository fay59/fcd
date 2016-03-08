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

#include "call_conv.h"
#include "cc_common.h"
#include "command_line.h"
#include "main.h"
#include "metadata.h"

#include <algorithm>

using namespace llvm;
using namespace std;

namespace
{
	void findUsedReturns(
		// invariant inputs
		const vector<const TargetRegisterInfo*>& returns,
		TargetInfo& targetInfo,
		MemorySSA& mssa,
		
		// inputs
		SmallPtrSetImpl<MemoryPhi*>& visited,
		MemoryAccess& access,
		
		// outputs
		vector<const TargetRegisterInfo*>& result)
	{
		for (auto user : access.users())
		{
			if (auto phi = dyn_cast<MemoryPhi>(user))
			{
				if (visited.insert(phi).second)
				{
					findUsedReturns(returns, targetInfo, mssa, visited, *phi, result);
				}
			}
			else if (auto use = dyn_cast<MemoryUse>(user))
			{
				if (auto load = dyn_cast<LoadInst>(use->getMemoryInst()))
				if (const TargetRegisterInfo* maybeReg = targetInfo.registerInfo(*load->getPointerOperand()))
				{
					bool alreadyFound = any_of(result.begin(), result.end(), [=](const TargetRegisterInfo* existing)
					{
						return existing == maybeReg;
					});
					
					if (!alreadyFound)
					{
						const TargetRegisterInfo* registerInfo = targetInfo.largestOverlappingRegister(*maybeReg);
						auto iter = find(returns.begin(), returns.end(), registerInfo);
						if (iter != returns.end())
						{
							// return value!
							result.push_back(registerInfo);
						}
					}
				}
			}
		}
	}
}

vector<const TargetRegisterInfo*> ipaFindUsedReturns(ParameterRegistry& registry, Function& function, const vector<const TargetRegisterInfo*>& returns)
{
	// Excuse entry points from not having callers; use every return.
	if (function.use_empty())
	if (auto address = md::getVirtualAddress(function))
	if (isEntryPoint(address->getLimitedValue()))
	{
		return returns;
	}
	
	// Otherwise, loop through callers and see which registers are used after the function call.
	TargetInfo& targetInfo = registry.getTargetInfo();
	SmallPtrSet<MemoryPhi*, 4> visited;
	vector<const TargetRegisterInfo*> result;
	for (auto& use : function.uses())
	{
		if (auto call = dyn_cast<CallInst>(use.getUser()))
		{
			auto parentFunction = call->getParent()->getParent();
			if (parentFunction == &function)
			{
				// TODO: This isn't impossible to compute, just somewhat inconvenient.
				continue;
			}
			
			auto parentArgs = static_cast<Argument*>(parentFunction->arg_begin());
			auto pointerType = dyn_cast<PointerType>(parentArgs->getType());
			assert(pointerType != nullptr && pointerType->getTypeAtIndex(int(0))->getStructName() == "struct.x86_regs");
			
			visited.clear();
			MemorySSA& mssa = *registry.getMemorySSA(*parentFunction);
			findUsedReturns(returns, targetInfo, mssa, visited, *mssa.getMemoryAccess(call), result);
		}
	}
	return result;
}

bool hackhack_fillFromParamInfo(LLVMContext& ctx, ParameterRegistry& registry, CallInformation& info, bool returns, size_t integerLikeParameters, bool isVariadic)
{
	TargetInfo& targetInfo = registry.getTargetInfo();
	Type* intType = Type::getIntNTy(ctx, targetInfo.getPointerSize() * CHAR_BIT);
	Type* returnType = returns ? intType : Type::getVoidTy(ctx);
	vector<Type*> params(integerLikeParameters, intType);
	FunctionType* fType = FunctionType::get(returnType, params, false);
	
	for (CallingConvention* cc : registry)
	{
		if (cc->analyzeFunctionType(registry, info, *fType))
		{
			info.setCallingConvention(cc);
			return true;
		}
		
		info.clear();
	}
	
	assert(false);
	return false;
}
