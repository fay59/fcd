//
//  pass_argrec.cpp
//  x86Emulator
//
//  Created by Félix on 2015-06-10.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#include "llvm_warnings.h"
#include "passes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/CallGraphSCCPass.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

namespace
{
	struct ArgumentRecovery : public CallGraphSCCPass
	{
		static char ID;
		
		ArgumentRecovery() : CallGraphSCCPass(ID)
		{
		}
		
		virtual void getAnalysisUsage(AnalysisUsage& au) const override
		{
			au.addRequired<AliasAnalysis>();
			CallGraphSCCPass::getAnalysisUsage(au);
		}
		
		virtual bool runOnSCC(CallGraphSCC& scc) override
		{
			return false;
		}
	};
	
	char ArgumentRecovery::ID = 0;
	RegisterPass<ArgumentRecovery> argrec("argrec", "Change functions to accept arguments instead of register struct", false, false);
}
