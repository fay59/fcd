//
// pass_modulethinner.cpp
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
#include "passes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

namespace
{
	struct ModuleThinner : public FunctionPass
	{
		static char ID;
		
		ModuleThinner()
		: FunctionPass(ID)
		{
		}
		
		virtual const char* getPassName() const override
		{
			return "Module Thinner";
		}
		
		bool isExcluded(Function& f)
		{
			if (isPartialDisassembly() && !f.isDeclaration())
			if (auto node = f.getMetadata("fcd.vaddr"))
			if (auto constantMD = dyn_cast<ConstantAsMetadata>(node->getOperand(0)))
			if (auto constantInt = dyn_cast<ConstantInt>(constantMD->getValue()))
			{
				return !hasEntryPoint(constantInt->getLimitedValue());
			}
			return false;
		}
		
		bool isImport(Function& f)
		{
			return f.getMetadata("fcd.importname") != nullptr;
		}
		
		virtual bool runOnFunction(Function& f) override
		{
			if (isExcluded(f) || isImport(f))
			{
				f.deleteBody();
				return true;
			}
			return false;
		}
	};
	
	char ModuleThinner::ID = 0;
	RegisterPass<ModuleThinner> moduleThinner("--module-thinner", "Delete unused function bodies", true, false);
}

FunctionPass* createModuleThinnerPass()
{
	return new ModuleThinner;
}
