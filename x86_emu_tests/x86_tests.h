//
//  x86_tests.h
//  x86Emulator
//
//  Created by Félix on 2015-04-26.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef DECLARE_TEST
# define DECLARE_TEST(x)
#endif

DECLARE_TEST(adc32)
DECLARE_TEST(adc64)
DECLARE_TEST(and32)
DECLARE_TEST(and64)
DECLARE_TEST(call)
DECLARE_TEST(cmov)
DECLARE_TEST(mov)

#undef DECLARE_TEST