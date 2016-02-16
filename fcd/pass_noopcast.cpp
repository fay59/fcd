//
// pass_noopcast.cpp
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
#include <llvm/IR/PatternMatch.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace llvm::PatternMatch;
using namespace std;

// This pass targets this pattern:
//
// %foo.stack = type { i64, i32, i32* }
// %field0 = getelementptr inbounds %foo.stack, %foo.stack* %0, i64 0, i32 1
// %field1 = getelementptr inbounds %foo.stack, %foo.stack* %0, i64 0, i32 2
// %x = ptrtoint i32* %field0 to i64
// %y = bitcast i32** %field1 to i64*
// store i64 %x, i64* %y, align 8
//
// In this case, it's possible to eliminate both casts and do a straight
// store i32* %field0, i32** %field1, align 8
// This helps SSA formation as ptrtoint kills SROA.
// It won't be necessary after LLVM unifies pointer types into a single `*` type.

namespace
{
	struct NoopCastEliminator : public FunctionPass
	{
		static char ID;
		
		NoopCastEliminator() : FunctionPass(ID)
		{
		}
		
		static Value* uncastedValue(Value* value)
		{
			while (auto cast = dyn_cast<CastInst>(value))
			{
				if (cast->getOpcode() == CastInst::Trunc)
				{
					break;
				}
				value = cast->getOperand(0);
			}
			return value;
		}
		
		virtual bool runOnFunction(Function& fn) override
		{
			bool changed = false;
			for (BasicBlock& bb : fn)
			{
				auto iter = bb.begin();
				while (iter != bb.end())
				{
					if (auto store = dyn_cast<StoreInst>(iter))
					{
						Value* pointer = store->getPointerOperand();
						Value* storeValue = store->getValueOperand();
						Value* uncastedPointer = uncastedValue(pointer);
						Value* uncastedStoreValue = uncastedValue(storeValue);
						if (pointer != uncastedPointer && storeValue != uncastedStoreValue)
						{
							if (uncastedStoreValue->getType()->getPointerTo() == uncastedPointer->getType())
							{
								StoreInst* result = new StoreInst(uncastedStoreValue, uncastedPointer, iter);
								store->eraseFromParent();
								iter = result;
								changed = true;
							}
						}
					}
					++iter;
				}
			}
			return changed;
		}
	};
	
	char NoopCastEliminator::ID = 0;
}

FunctionPass* createNoopCastEliminationPass()
{
	return new NoopCastEliminator;
}

