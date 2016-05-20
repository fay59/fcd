//
// pass_fixind.cpp
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

#include "main.h"
#include "metadata.h"
#include "params_registry.h"
#include "pass_argrec.h"
#include "passes.h"

#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Function.h>

using namespace llvm;
using namespace std;

namespace
{
	struct FixIndirect final : public ModulePass
	{
		static char ID;
		
		FixIndirect() : ModulePass(ID)
		{
		}
		
		virtual void getAnalysisUsage(AnalysisUsage& au) const override
		{
			au.addRequired<ParameterRegistry>();
			ModulePass::getAnalysisUsage(au);
		}
		
		virtual bool runOnModule(Module& m) override
		{
			// FIXME: avoid references to x86 intrinsics directly.
			
			bool changed = false;
			if (Function* indJump = m.getFunction("x86_jump_intrin"))
			{
				changed |= fixIndirectJumps(*indJump);
			}
			
			if (Function* indCall = m.getFunction("x86_call_intrin"))
			{
				changed |= fixIndirectCalls(*indCall);
			}
			
			return changed;
		}
		
		bool fixIndirectJumps(Function& callIntrin)
		{
			bool changed = false;
			
			// TODO: this only merely makes fcd not fail in the presence of indirect calls, it doesn't actually do
			// meaningful analysis.
			
			auto& module = *callIntrin.getParent();
			auto& context = module.getContext();
			Type* intptrTy = module.getDataLayout().getIntPtrType(Type::getInt8PtrTy(context));
			Type* voidTy = Type::getVoidTy(context);
			auto indirectJump = cast<Function>(module.getOrInsertFunction("__indirect_jump", voidTy, intptrTy, nullptr));
			indirectJump->setDoesNotReturn();
			
			for (Value* user : vector<Value*>(callIntrin.user_begin(), callIntrin.user_end()))
			{
				if (auto call = dyn_cast<CallInst>(user))
				{
					Value* destination = call->getArgOperand(2);
					auto intptrDestination = CastInst::Create(CastInst::IntToPtr, destination, intptrTy, "", call);
					CallInst::Create(indirectJump, { intptrDestination }, "", call);
					call->eraseFromParent();
				}
			}
			
			return changed;
		}
		
		bool fixIndirectCalls(Function& callIntrin)
		{
			bool changed = false;
			
			ParameterRegistry& params = getAnalysis<ParameterRegistry>();
			auto target = TargetInfo::getTargetInfo(*callIntrin.getParent());
			
			// copy the list as we will replace instructions
			for (Value* user : vector<Value*>(callIntrin.user_begin(), callIntrin.user_end()))
			{
				if (auto call = dyn_cast<CallInst>(user))
				if (auto info = params.analyzeCallSite(CallSite(call)))
				{
					Function& parent = *call->getParent()->getParent();
					Module& module = *parent.getParent();
					
					string typeName;
					raw_string_ostream(typeName) << "__indirect__" << parent.getName() << "__" << static_cast<void*>(call);
					
					FunctionType* ft = ArgumentRecovery::createFunctionType(*target, *info, module, typeName);
					Value* callable = CastInst::CreateBitOrPointerCast(call->getOperand(2), ft->getPointerTo(), "", call);
					Value* registers = call->getOperand(1);
					CallInst* result = ArgumentRecovery::createCallSite(*target, *info, *callable, *registers, *call);
					result->takeName(call);
					call->eraseFromParent();
				}
			}
			
			return changed;
		}
	};
	
	char FixIndirect::ID = 0;
	RegisterPass<FixIndirect> fixIndirects("fixindirects", "Get rid of indirect call/jump intrinsics");
}

ModulePass* createFixIndirectsPass()
{
	return new FixIndirect;
}

