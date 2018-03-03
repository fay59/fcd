//
// cc_common.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__callconv_cc_common_h
#define fcd__callconv_cc_common_h

#include "params_registry.h"
#include "targetinfo.h"

#include <llvm/IR/Function.h>

#include <vector>

std::vector<const TargetRegisterInfo*> ipaFindUsedReturns(ParameterRegistry& registry, llvm::Function& function, const std::vector<const TargetRegisterInfo*>& returns);
bool hackhack_fillFromParamInfo(llvm::LLVMContext& ctx, ParameterRegistry& registry, CallInformation& info, bool returns, size_t integerLikeParameters, bool isVariadic);
bool hackhack_fillFromPrototype(llvm::Function& prototype, ParameterRegistry& registry, CallInformation& info);

#endif /* fcd__callconv_cc_common_h */
