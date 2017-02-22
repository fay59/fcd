//
// incbin.osx.tpl
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

// This file is used by the build system as a template to generate
// LLVM bitcode symbols. {CPU} is substituted with the actual
// architecture name (for instance: _fcd_emulator_start_myneatcpu).

	.const_data
	.private_extern _fcd_emulator_start_{CPU}
	.private_extern _fcd_emulator_end_{CPU}
_fcd_emulator_start_{CPU}:
	.incbin "{CPU}.emulator.cpp.bc"
_fcd_emulator_end_{CPU}:
