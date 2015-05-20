//
//  passes.h
//  x86Emulator
//
//  Created by Félix on 2015-04-21.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __x86Emulator__asaa__
#define __x86Emulator__asaa__

#include <llvm/Pass.h>
#include <llvm/Analysis/CallGraphSCCPass.h>

llvm::ImmutablePass* createAddressSpaceAliasAnalysisPass();
llvm::FunctionPass* createIntegerDemotionPass();
llvm::ModulePass* createArgumentRecoveryPass();

namespace llvm
{
	void initializeArgumentRecoveryPass(PassRegistry& PR);
}

#endif /* defined(__x86Emulator__asaa__) */
