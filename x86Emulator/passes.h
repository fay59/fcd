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
#include <llvm/Analysis/CallGraphSCCPass.h>
SILENCE_LLVM_WARNINGS_END()

llvm::ImmutablePass* createAddressSpaceAliasAnalysisPass();
llvm::FunctionPass* createIntegerDemotionPass();
llvm::ModulePass* createRegisterUsePass();

namespace llvm
{
	void initializeRegisterUsePass(PassRegistry& PR);
}

#endif /* defined(__x86Emulator__asaa__) */
