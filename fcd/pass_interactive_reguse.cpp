//
// pass_interactive_reguse.cpp
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
#include <llvm/IR/Constants.h>
SILENCE_LLVM_WARNINGS_END()

#include <iomanip>
#include <iostream>
#include <string>

using namespace llvm;
using namespace std;

namespace
{
	template<typename T, size_t N>
	constexpr size_t countof(T (&)[N])
	{
		return N;
	}
	
	bool functionAddress(Function* fn, uint64_t* output)
	{
		if (auto node = fn->getMetadata("fcd.vaddr"))
		if (auto constantMD = dyn_cast<ConstantAsMetadata>(node->getOperand(0)))
		if (auto constantInt = dyn_cast<ConstantInt>(constantMD->getValue()))
		{
			*output = constantInt->getLimitedValue();
			return true;
		}
		return false;
	}
	
	struct InteractiveRegisterUse : public ModulePass
	{
		static char ID;
		
		InteractiveRegisterUse() : ModulePass(ID)
		{
		}
		
		virtual void getAnalysisUsage(AnalysisUsage &au) const override
		{
			au.addRequired<TargetInfo>();
			au.addRequired<RegisterUseWrapper>();
			ModulePass::getAnalysisUsage(au);
		}
		
		virtual const char* getPassName() const override
		{
			return "Interactive Register Use";
		}
		
		virtual bool runOnModule(Module& m) override
		{
			TargetInfo& info = getAnalysis<TargetInfo>();
			RegisterUseWrapper& regUse = getAnalysis<RegisterUseWrapper>();
			for (Function& function : m.getFunctionList())
			{
				if (function.isDeclaration() && function.getNumUses() == 0)
				{
					continue;
				}
				
				if (regUse.getModRefInfo(&function) != nullptr)
				{
					continue;
				}
				
				cout << function.getName().str();
				uint64_t address;
				if (functionAddress(&function, &address))
				{
					cout << " [" << hex << setfill('0') << setw(info.getPointerSize() * 2) << address << ']';
				}
				cout << " needs register use information." << endl;
				
				char yesNoReturns;
				do
				{
					cout << "Does it have a return value? [y/n] " << flush;
					
					cin.clear(cin.rdstate() & ~ios::failbit);
					if (cin)
					{
						cin >> yesNoReturns;
					}
					else
					{
						yesNoReturns = 'n';
					}
				}
				while (cin.fail() || (yesNoReturns != 'y' && yesNoReturns != 'n'));
				
				unsigned numberOfParameters;
				do
				{
					cout << "How many parameters does it have? " << flush;
					cin.clear(cin.rdstate() & ~ios::failbit);
					if (cin)
					{
						cin >> numberOfParameters;
					}
					else
					{
						numberOfParameters = 0;
					}
				}
				while (cin.fail());
				
				hackhack_systemVabi(info, regUse.getOrCreateModRefInfo(&function), yesNoReturns == 'y', numberOfParameters);
			}
			return false;
		}
		
		// This needs to be updated to support multiple front-ends
		void hackhack_systemVabi(const TargetInfo& x86Info, RegisterUse::mapped_type& table, bool returns, unsigned argcount)
		{
			static const char* const argumentRegs[] = {
				"rdi", "rsi", "rdx", "rcx", "r8", "r9"
			};
			
			table[x86Info.keyName("rax")] = returns ? AliasAnalysis::Mod : AliasAnalysis::NoModRef;
			table[x86Info.keyName("rbx")] = AliasAnalysis::NoModRef;
			
			table[x86Info.keyName("r10")] = AliasAnalysis::NoModRef;
			table[x86Info.keyName("r11")] = AliasAnalysis::NoModRef;
			table[x86Info.keyName("r12")] = AliasAnalysis::NoModRef;
			table[x86Info.keyName("r13")] = AliasAnalysis::NoModRef;
			table[x86Info.keyName("r14")] = AliasAnalysis::NoModRef;
			table[x86Info.keyName("r15")] = AliasAnalysis::NoModRef;
			
			table[x86Info.keyName("rbp")] = AliasAnalysis::NoModRef;
			table[x86Info.keyName("rsp")] = AliasAnalysis::NoModRef;
			table[x86Info.keyName("rip")] = AliasAnalysis::NoModRef;
			
			for (size_t i = 0; i < countof(argumentRegs); i++)
			{
				const char* uniqued = x86Info.keyName(argumentRegs[i]);
				table[uniqued] = i < argcount ? AliasAnalysis::Ref : AliasAnalysis::NoModRef;
			}
		}
	};
	
	char InteractiveRegisterUse::ID = 0;
}

ModulePass* createInteractiveRegisterUsePass()
{
	return new InteractiveRegisterUse;
}

INITIALIZE_PASS_BEGIN(InteractiveRegisterUse, "interactivereguse", "Interactive resolution of register use", false, true)
INITIALIZE_PASS_DEPENDENCY(TargetInfo)
INITIALIZE_PASS_DEPENDENCY(RegisterUseWrapper)
INITIALIZE_PASS_END(InteractiveRegisterUse, "interactivereguse", "Interactive resolution of register use", false, true)
