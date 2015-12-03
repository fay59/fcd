//
// cc_common.h
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

#ifndef cc_common_hpp
#define cc_common_hpp

#include "llvm_warnings.h"
#include "targetinfo.h"
#include "params_registry.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Function.h>
SILENCE_LLVM_WARNINGS_END()

#include <vector>

std::vector<const TargetRegisterInfo*> ipaFindUsedReturns(ParameterRegistry& registry, llvm::Function& function, const std::vector<const TargetRegisterInfo*>& returns);
bool hackhack_fillFromParamInfo(llvm::LLVMContext& ctx, ParameterRegistry& registry, CallInformation& info, bool returns, size_t integerLikeParameters, bool isVariadic);

#endif /* cc_common_hpp */
