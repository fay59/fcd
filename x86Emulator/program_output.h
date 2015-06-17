//
//  program_output.hpp
//  x86Emulator
//
//  Created by Félix on 2015-06-16.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#ifndef program_output_cpp
#define program_output_cpp

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Analysis/RegionPass.h>
SILENCE_LLVM_WARNINGS_END()

llvm::RegionPass* createEmitCRegionPass();

namespace llvm
{
	void initializeEmitCRegionPass(PassRegistry& pr);
}

#endif /* program_output_cpp */
