//
// passes.h
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

#ifndef fcd__passes_h
#define fcd__passes_h

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Pass.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/Passes.h>
#include "MemorySSA.h"
SILENCE_LLVM_WARNINGS_END()

#include "pass_argrec.h"
#include "pass_backend.h"
#include "pass_executable.h"
#include "pass_regaa.h"
#include "pass_seseloop.h"
#include "targetinfo.h"

llvm::FunctionPass*		createConditionSimplificationPass();
llvm::ModulePass*		createFixIndirectsPass();
llvm::ModulePass*		createIdentifyLocalsPass();
llvm::FunctionPass*		createIntNarrowingPass();
llvm::FunctionPass*		createMemorySSADeadLoadEliminationPass();
llvm::ModulePass*		createModuleThinnerPass();
llvm::FunctionPass*		createNoopCastEliminationPass();
llvm::FunctionPass*		createRegisterPointerPromotionPass();
llvm::FunctionPass*		createSignExtPass();
llvm::FunctionPass*		createSwitchRemoverPass();
TargetInfo*				createTargetInfoPass();

namespace llvm
{
	void initializeAstBackEndPass(PassRegistry& pr);
	void initializeSESELoopPass(PassRegistry& pr);
}

#endif /* defined(fcd__passes_h) */
