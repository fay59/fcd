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
DECLARE_TEST(cmp)
DECLARE_TEST(imul32)
DECLARE_TEST(imul64)
DECLARE_TEST(j)
DECLARE_TEST(jcxz)
DECLARE_TEST(lea)
DECLARE_TEST(leave)
DECLARE_TEST(mov8)
DECLARE_TEST(mov16)
DECLARE_TEST(mov32)
DECLARE_TEST(mov64)
DECLARE_TEST(movzx8_16)
DECLARE_TEST(movzx16_64)
DECLARE_TEST(not)
DECLARE_TEST(or)
DECLARE_TEST(pop)

// !! One test per set* instruction

#undef DECLARE_TEST