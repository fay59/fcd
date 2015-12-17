//
// pass_locals.cpp
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
#include <llvm/IR/PatternMatch.h>
SILENCE_LLVM_WARNINGS_END()

#include <vector>

using namespace llvm;
using namespace llvm::PatternMatch;
using namespace std;

namespace
{
	// This pass needs to run AFTER argument recovery.
	// XXX: This pass assumes a stack that grows downwards.
	struct IdentifyLocals : public FunctionPass
	{
		static char ID;
		
		IdentifyLocals() : FunctionPass(ID)
		{
		}
		
		virtual const char* getPassName() const override
		{
			return "Identify locals";
		}
		
		Argument* getStackPointer(Function& fn)
		{
			ConstantInt* stackPointerIndex = md::getStackPointerArgument(fn);
			if (stackPointerIndex == nullptr)
			{
				return nullptr;
			}
			
			auto arg = fn.arg_begin();
			advance(arg, stackPointerIndex->getLimitedValue());
			return arg;
		}
		
		virtual bool runOnFunction(Function& fn) override
		{
			Argument* stackPointer = getStackPointer(fn);
			if (stackPointer == nullptr)
			{
				return false;
			}
			
			// list values that use the stack pointer
			int64_t stackDepth = 0;
			vector<Value*> spUses;
			spUses.push_back(stackPointer);
			for (size_t i = 0; i < spUses.size(); ++i)
			{
				// Add values to set of possible sp references, and try to infer stack depth.
				// Stack depth can only look at instructions of the form "add <sp>, <offset>".
				Value* thisValue = spUses[i];
				for (User* user : thisValue->users())
				{
					if (auto binOp = dyn_cast<BinaryOperator>(user))
					{
						spUses.push_back(binOp);
						ConstantInt* offset;
						if (thisValue == stackPointer && match(binOp, m_Add(m_Value(), m_ConstantInt(offset))))
						{
							int64_t thisDepth = offset->getLimitedValue();
							stackDepth = min(stackDepth, thisDepth);
						}
					}
				}
			}
			
			errs() << "Stack depth is " << -stackDepth << "\n";
			for (Value* v : spUses)
			{
				v->dump();
			}
			
			return false;
		}
	};
	
	char IdentifyLocals::ID = 0;
	RegisterPass<IdentifyLocals> identifyLocals("--identify-locals", "Identify local variables", false, false);
}

FunctionPass* createIdentifyLocalsPass()
{
	return new IdentifyLocals;
}
