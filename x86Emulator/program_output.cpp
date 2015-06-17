//
//  program_output.cpp
//  x86Emulator
//
//  Created by Félix on 2015-06-16.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#include "program_output.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Analysis/RegionPass.h>
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
SILENCE_LLVM_WARNINGS_END()

#include <iostream>

using namespace llvm;
using namespace std;

namespace
{
	struct EmitCRegion : public RegionPass
	{
		static char ID;
		
		EmitCRegion() : RegionPass(ID)
		{
		}
		
		virtual bool runOnRegion(Region* r, RGPassManager& rgm) override
		{
			return false;
		}
	};
	
	char EmitCRegion::ID = 0;
}

RegionPass* createEmitCRegionPass()
{
	return new EmitCRegion;
}

INITIALIZE_PASS_BEGIN(EmitCRegion, "ecr", "Emit C for region", false, false)
INITIALIZE_PASS_DEPENDENCY(RegionInfoPass)
INITIALIZE_PASS_END(EmitCRegion, "ecr", "Emit C for region", false, false)
