//
//  passes.h
//  x86Emulator
//
//  Created by Félix on 2015-04-21.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
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

#include "pass_targetinfo.h"
#include "pass_reguse.h"
#include "program_output.h"

llvm::ImmutablePass* createAddressSpaceAliasAnalysisPass();
llvm::CallGraphSCCPass* createArgumentRecoveryPass();
AstBackEnd* createAstBackEnd();
llvm::FunctionPass* createRegisterPointerPromotionPass();
RegisterUse* createRegisterUsePass();
llvm::FunctionPass* createSESELoopPass();
TargetInfo* createTargetInfoPass();

namespace llvm
{
	void initializeArgumentRecoveryPass(PassRegistry& pm);
	void initializeAstBackEndPass(PassRegistry& pm);
	void initializeSESELoopPass(PassRegistry& pm);
}

#endif /* defined(__x86Emulator__asaa__) */
