//
// incbin.linux.tpl
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
