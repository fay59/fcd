//
// pass_regptrpromotion.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "metadata.h"
#include "passes.h"

#include <llvm/Analysis/Passes.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

using namespace llvm;
using namespace std;

namespace
{
	// This pass is a little bit of a hack.
	// Emulators create weird code for union access. Bitcasts that target just part of a register use a GEP to
	// the struct that encloses the i64. The address is the same, but the type is different, and this angers
	// argument promotion. This pass fixes the GEPs to always use the i64 pointer.
	struct RegisterPointerPromotion final : public FunctionPass
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
				auto firstArg = &*f.arg_begin();
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
	RegisterPass<RegisterPointerPromotion> regPass("#rptrp", "Register Pointer Promotion", false, false);
}

FunctionPass* createRegisterPointerPromotionPass()
{
	return new RegisterPointerPromotion;
}
