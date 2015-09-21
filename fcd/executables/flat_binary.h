//
// flat_binary.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is part of fcd. fcd as a whole is licensed under the terms
// of the GNU GPLv3 license, but specific parts (such as this one) are
// dual-licensed under the terms of a BSD-like license as well. You
// may use, modify and distribute this part of fcd under the terms of
// either license, at your choice. See the LICENSE file in this directory
// for details.
//

#ifndef flat_binary_hpp
#define flat_binary_hpp

#include "executable.h"

llvm::ErrorOr<std::unique_ptr<Executable>> parseFlatBinary(const uint8_t* begin, const uint8_t* end);

#endif /* flat_binary_hpp */
