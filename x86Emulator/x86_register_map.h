//
//  x86_register_map.h
//  x86Emulator
//
//  Created by Félix on 2015-05-04.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __x86Emulator__x86_register_map__
#define __x86Emulator__x86_register_map__

#include <cstddef>

const char* x86_get_register_name(size_t offset, size_t size);

#endif /* defined(__x86Emulator__x86_register_map__) */
