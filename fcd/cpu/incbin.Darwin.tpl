//
// incbin.osx.tpl
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
// architecture name (for instance: _fcd_emulator_start_myneatcpu).

	.const_data
	.private_extern _fcd_emulator_start_{CPU}
	.private_extern _fcd_emulator_end_{CPU}
_fcd_emulator_start_{CPU}:
	.incbin "{CPU}.emulator.cpp.bc"
_fcd_emulator_end_{CPU}:
