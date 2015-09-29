//
// x86_64_systemv.cpp
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

// About the x86_64 SystemV calling convention:
// http://x86-64.org/documentation/abi.pdf pp 20-22
// In short, for arguments:
// - Aggregates are passed in registers, unless one of the fields is a floating-point field, in which case it goes to
//		memory; or unless not enough registers are available, in which case it also goes to the stack.
// - Integral arguments are passed in rdi-rsi-dxc-rcx-r8-r9.
// - Floating-point arguments are passed in [xyz]mm0-[xyz]mm7
// - Anything else/left remaining goes to the stack.
// For return values:
// - Integral values go to rax-rdx.
// - Floating-point values go to xmm0-xmm1.
// - Large return values may be written to *rdi, and rax will contain rdi (in which case it's indistinguishible from
//		a function accepting the output destination as a first parameter).
// The relative parameter order of values of different classes is not preserved.

#include "x86_64_systemv.h"

using namespace llvm;
using namespace std;

namespace
{
	RegisterCallingConvention<CallingConvention_x86_64_systemv> registerSysV;
}

unique_ptr<CallInformation> CallingConvention_x86_64_systemv::analyzeFunction(ParameterRegistry& params, Function &function)
{
	// Find rsp, check for pointers above the stack
	// Look at registers directly used (registers that were read before being written)
	// Look at return registers, analyze callers to see which registers are read after being used
	// Look at called functions to find "hidden parameters"
	
	return nullptr;
}

bool CallingConvention_x86_64_systemv::matches(TargetInfo &target, Executable &executable) const
{
	return target.targetName().substr(3) == "x86" && executable.getExecutableType().substr(6) == "ELF 64";
}

const char* CallingConvention_x86_64_systemv::getName() const
{
	return "x86_64 System V";
}
