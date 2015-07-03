//
//  llvm_warnings.h
//  x86Emulator
//
//  Created by Félix on 2015-05-28.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
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