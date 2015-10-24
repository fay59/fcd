//
// pass_conditions.cpp
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

#include "passes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/IntrinsicInst.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

namespace
{
	struct ConditionSimplification : public FunctionPass
	{
		static char ID;
		
		ConditionSimplification() : FunctionPass(ID)
		{
		}
		
		virtual bool runOnFunction(Function& fn) override
		{
			bool result = false;
			for (auto& bb : fn)
			{
				result |= runOnBasicBlock(bb);
			}
			return result;
		}
		
		bool runOnBasicBlock(BasicBlock& bb)
		{
			bool result = false;
			// Attempt to remove uses of usub_with_overflow by replacig its bool element with icmp ult.
			for (auto& inst : bb)
			{
				if (inst.getOpcode() == Instruction::Call)
				if (auto intrin = dyn_cast<IntrinsicInst>(&inst))
				if (intrin->getIntrinsicID() == Intrinsic::usub_with_overflow)
				{
					result |= replaceUsubWithOverflow(*intrin);
				}
			}
			return result;
		}
		
		bool replaceUsubWithOverflow(IntrinsicInst& inst)
		{
			// This doesn't actually remove the usub_with_overflow, it merely replaces uses of its
			// boolean return value.
			bool result = false;
			for (auto& use : inst.uses())
			{
				if (auto extract = dyn_cast<ExtractValueInst>(use.getUser()))
				if (*extract->idx_begin() == 1)
				{
					assert(extract->getNumIndices() == 1);
					auto icmp = ICmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_ULT, inst.getOperand(0), inst.getOperand(1), "", extract);
					extract->replaceAllUsesWith(icmp);
					result = true;
				}
				
			}
			return result;
		}
	};
	
	char ConditionSimplification::ID = 0;
}

FunctionPass* createConditionSimplificationPass()
{
	return new ConditionSimplification;
}
