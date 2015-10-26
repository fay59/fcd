//
// x86_64_systemv.cpp
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

// About the x86_64 SystemV calling convention:
// http://x86-64.org/documentation/abi.pdf pp 20-22
// In short, for arguments:
// - Aggregates are passed in registers, unless one of the fields is a floating-point field, in which case it goes to
//		memory; or unless not enough integer registers are available, in which case it also goes to the stack.
// - Integral arguments are passed in rdi-rsi-rdx-rcx-r8-r9.
// - Floating-point arguments are passed in [xyz]mm0-[xyz]mm7
// - Anything else/left remaining goes to the stack.
// For return values:
// - Integral values go to rax-rdx.
// - Floating-point values go to xmm0-xmm1.
// - Large return values may be written to *rdi, and rax will contain rdi (in which case it's indistinguishible from
//		a function accepting the output destination as a first parameter).
// The relative parameter order of values of different classes is not preserved.

#include "x86_64_systemv.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/PatternMatch.h>
#include "MemorySSA.h"
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace llvm::PatternMatch;
using namespace std;

namespace
{
	struct x86_64_systemv : public ParameterIdentificationPass
	{
		static char ID;
		
		x86_64_systemv() : ParameterIdentificationPass(ID)
		{
		}
		
		virtual void analyzeFunction(ParameterRegistry& params, CallInformation& callInfo, Function &function) override
		{
			// Does the function refer to values at an offset above the initial rsp value?
			// Assume that rsp is known to be preserved.
			assert(function.arg_size() == 1);
			Argument* regs = function.arg_begin();
			
			// (assume x86 regs as first parameter)
			auto pointerType = dyn_cast<PointerType>(regs->getType());
			assert(pointerType != nullptr && pointerType->getTypeAtIndex(int(0))->getStructName() == "struct.x86_regs");
			
			SmallVector<Value*, 1> spValues;
			const auto& stackPointer = *params.getTarget().getStackPointer();
			for (auto& use : regs->uses())
			{
				Value* v = use.get();
				if (const char* regName = params.getTarget().registerName(*v))
					if (stackPointer.name == regName)
					{
						// Find all uses of reference to sp register
						for (auto& use : v->uses())
						{
							if (auto load = dyn_cast<LoadInst>(use.getUser()))
							{
								spValues.push_back(load);
							}
						}
					}
			}
			
			for (Value* sp : spValues)
			{
				// Find uses above +8 (since +0 is the return address)
				for (auto& use : sp->uses())
				{
					ConstantInt* offset = nullptr;
					if (match(cast<Value>(use), m_Add(m_Value(), m_ConstantInt(offset))))
					{
						make_signed<decltype(offset->getLimitedValue())>::type intOffset = offset->getLimitedValue();
						if (intOffset > 8)
						{
							// memory argument! wat do?
							assert(false);
						}
					}
				}
			}
			
			// Look at registers that are directly used (registers that were read before being written)
			const char* registerNames[] = { "rdi", "rsi", "rdx", "rcx", "r8", "r9" };
			for (const char* name : registerNames)
			{
				
			}
			
			// Look at return registers, analyze callers to see which registers are read after being used
			// Look at called functions to find "hidden parameters"
		}
	};
	
	char x86_64_systemv::ID = 0;
	
	RegisterCallingConvention<CallingConvention_x86_64_systemv> registerSysV;
}

bool CallingConvention_x86_64_systemv::matches(TargetInfo &target, Executable &executable) const
{
	return target.targetName().substr(3) == "x86" && executable.getExecutableType().substr(6) == "ELF 64";
}

const char* CallingConvention_x86_64_systemv::getName() const
{
	return "x86_64 System V";
}

unique_ptr<ParameterIdentificationPass> CallingConvention_x86_64_systemv::doCreatePass()
{
	return std::make_unique<x86_64_systemv>();
}
