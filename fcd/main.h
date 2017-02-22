//
// main.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__main_h
#define fcd__main_h

#include <cstdint>

bool isFullDisassembly();
bool isPartialDisassembly();
bool isExclusiveDisassembly();
bool isEntryPoint(uint64_t ep);

#endif /* fcd__main_h */
