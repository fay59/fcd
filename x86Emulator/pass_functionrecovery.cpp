//
//  pass_functionrecovery.cpp
//  x86Emulator
//
//  Created by Félix on 2015-05-01.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include "passes.h"

using namespace llvm;
using namespace std;

namespace
{
	struct FunctionRecoveryPass : public CallGraphSCCPass
	{
		static char ID;
		
		FunctionRecoveryPass() : CallGraphSCCPass(ID)
		{
		}
		
		virtual bool runOnSCC(CallGraphSCC& scc) override
		{
			return false;
		}
	};
	
	char FunctionRecoveryPass::ID = 0;
	RegisterPass<FunctionRecoveryPass> functionRecovery("func-recov", "Recover function parameters and returns", false, false);
}

CallGraphSCCPass* createFunctionRecoveryPass()
{
	return new FunctionRecoveryPass;
}
