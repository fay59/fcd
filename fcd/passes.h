//
// passes.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__passes_h
#define fcd__passes_h

#include <llvm/Pass.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Transforms/Utils/MemorySSA.h>

#include "pass_argrec.h"
#include "pass_backend.h"
#include "pass_executable.h"
#include "pass_regaa.h"
#include "targetinfo.h"

llvm::FunctionPass*		createRegisterPointerPromotionPass();

#endif /* defined(fcd__passes_h) */
