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
#include "metadata.h"
#include "passes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

namespace
{
	struct ModuleThinner final : public ModulePass
	{
		static char ID;
		
		ModuleThinner()
		: ModulePass(ID)
		{
		}
		
		virtual const char* getPassName() const override
		{
			return "Module Thinner";
		}
		
		bool isExcluded(Function& f)
		{
			if (isPartialDisassembly() && !md::isPrototype(f))
			if (auto addr = md::getVirtualAddress(f))
			{
				return !isEntryPoint(addr->getLimitedValue());
			}
			
			return false;
		}
		
		bool isImport(Function& f)
		{
			return md::getImportName(f) != nullptr;
		}
		
		virtual bool runOnModule(Module& m) override
		{
			bool changed = false;
			for (Function& f : m.getFunctionList())
			{
				if (isExcluded(f) || isImport(f))
				{
					f.deleteBody();
					md::setIsPartOfOutput(f);
					changed = true;
				}
			}
			return changed;
		}
	};
	
	char ModuleThinner::ID = 0;
	RegisterPass<ModuleThinner> moduleThinner("modulethinner", "Delete unused function bodies");
}

ModulePass* createModuleThinnerPass()
{
	return new ModuleThinner;
}
