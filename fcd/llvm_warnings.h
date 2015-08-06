//
// llvm_warnings.h
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

// By default, Xcode tells Clang to complain about truncated integers. Rather than disabling that warning for the whole
// project, we guard #include <llvm/...> statements with these macros that disable them temporarily only.

#ifndef SILENCE_LLVM_WARNINGS_BEGIN

#define SILENCE_LLVM_WARNINGS_BEGIN() \
	_Pragma("clang diagnostic push") \
	_Pragma("clang diagnostic ignored \"-Wshorten-64-to-32\"")

#define SILENCE_LLVM_WARNINGS_END() \
	_Pragma("clang diagnostic pop")

#endif