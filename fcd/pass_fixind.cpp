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

#include "llvm_warnings.h"
#include "main.h"
#include "metadata.h"
#include "params_registry.h"
#include "pass_argrec.h"
#include "passes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

namespace
{
	struct FixIndirect : public ModulePass
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
		
		bool fixIndirectJumps(Function& indirect)
		{
			bool changed = false;
			
			// TODO: tail calls, jump tables
			
			return changed;
		}
		
		bool fixIndirectCalls(Function& indirect)
		{
			bool changed = false;
			
			ParameterRegistry& params = getAnalysis<ParameterRegistry>();
			auto target = TargetInfo::getTargetInfo(*indirect.getParent());
			
			for (Value* user : vector<Value*>(indirect.user_begin(), indirect.user_end()))
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
	RegisterPass<FixIndirect> moduleThinner("--fix-indirects", "Get rid of indirect call/jump intrinsics", true, false);
}

ModulePass* createFixIndirectsPass()
{
	return new FixIndirect;
}

