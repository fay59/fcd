//
// incbin.linux.tpl
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

// This file is used by the build system as a template to generate
// LLVM bitcode symbols. {CPU} is substituted with the actual
// architecture name (for instance: fcd_emulator_start_myneatcpu).

// The symbols don't need to be global. On OS X, they are private_extern.
// However, that modifier doesn't exist on Linux (apparently), so they are
// global since there is little harm in that. These symbols need to be visible
// from other translation units but can be stripped from the final product.
// If you know how to make that happen, you are welcome to do it or tell me how.

// Additionally, on Mac OS X, the symbols are marked with ".const_data", making
// the symbol data read-only and non-executable. This is again (probably) not
// such a big deal, but it would be better with Linux if we could avoid it.

	.globl fcd_emulator_start_{CPU}
	.globl fcd_emulator_end_{CPU}
fcd_emulator_start_{CPU}:
	.incbin "{CPU}.emulator.bc"
fcd_emulator_end_{CPU}:
