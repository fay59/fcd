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

#ifndef __x86Emulator__asaa__
#define __x86Emulator__asaa__

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Pass.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/CallGraphSCCPass.h>
#include <llvm/Analysis/LoopPass.h>
#include <llvm/Analysis/Passes.h>
SILENCE_LLVM_WARNINGS_END()

#include <unordered_map>
#include <unordered_set>

#include "ast_backend.h"
#include "pass_targetinfo.h"
#include "pass_reguse.h"

llvm::ImmutablePass* createAddressSpaceAliasAnalysisPass();
llvm::CallGraphSCCPass* createArgumentRecoveryPass();
AstBackEnd* createAstBackEnd();
llvm::FunctionPass* createRegisterPointerPromotionPass();
RegisterUse* createRegisterUsePass();
llvm::FunctionPass* createLoopCollapseEntriesPass();
TargetInfo* createTargetInfoPass();

namespace llvm
{
	void initializeArgumentRecoveryPass(PassRegistry& pm);
	void initializeAstBackEndPass(PassRegistry& pm);
	void initializeLoopCollapseEntriesPass(PassRegistry& pm);
}

#endif /* defined(__x86Emulator__asaa__) */
