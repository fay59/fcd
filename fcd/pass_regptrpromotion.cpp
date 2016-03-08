//
// pass_regptrpromotion.cpp
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
#include "metadata.h"
#include "passes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Analysis/Passes.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

namespace
{
	// This pass is a little bit of a hack.
	// Emulators create weird code for union access. Bitcasts that target just part of a register use a GEP to
	// the struct that encloses the i64. The address is the same, but the type is different, and this angers
	// argument promotion. This pass fixes the GEPs to always use the i64 pointer.
	struct RegisterPointerPromotion : public FunctionPass
	{
		static char ID;
		
		RegisterPointerPromotion() : FunctionPass(ID)
		{
		}
		
		virtual bool runOnFunction(Function& f) override
		{
			bool modified = false;
			if (md::areArgumentsRecoverable(f))
			{
				assert(f.arg_size() == 1);
				
				// Copy arguments to independent list to avoid iterating while modifying.
				auto firstArg = static_cast<Argument*>(f.arg_begin());
				SmallVector<User*, 16> users(firstArg->user_begin(), firstArg->user_end());
				for (auto user : users)
				{
					if (auto gep = dyn_cast<GetElementPtrInst>(user))
					if (isa<StructType>(gep->getResultElementType()))
					{
						fixGep(*gep);
						modified = true;
					}
				}
			}
			return modified;
		}
		
		void fixGep(GetElementPtrInst& gep)
		{
			LLVMContext& ctx = gep.getContext();
			SmallVector<Value*, 4> indices(gep.idx_begin(), gep.idx_end());
			indices.push_back(ConstantInt::get(Type::getInt32Ty(ctx), 0));
			GetElementPtrInst* goodGep = GetElementPtrInst::CreateInBounds(gep.getPointerOperand(), indices, "", &gep);
			
			bool allRemoved = true;
			// We can't use replaceAllUsesWith because the type is different.
			SmallVector<User*, 4> users(gep.user_begin(), gep.user_end());
			for (User* user : users)
			{
				if (auto badCast = dyn_cast<CastInst>(user))
				{
					auto goodCast = CastInst::Create(badCast->getOpcode(), goodGep, badCast->getType(), "", badCast);
					badCast->replaceAllUsesWith(goodCast);
					
					goodCast->takeName(badCast);
					badCast->eraseFromParent();
				}
				else
				{
					allRemoved = false;
				}
			}
			
			if (allRemoved)
			{
				// Let some other pass delete the instruction.
				goodGep->takeName(&gep);
			}
		}
	};
	
	char RegisterPointerPromotion::ID = 0;
	RegisterPass<RegisterPointerPromotion> regPass("rptrp", "Register Pointer Promotion", false, false);
}

FunctionPass* createRegisterPointerPromotionPass()
{
	return new RegisterPointerPromotion;
}
