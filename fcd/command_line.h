//
// command_line.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__command_line_h
#define fcd__command_line_h


#include <llvm/Support/CommandLine.h>

struct whitelist
{
	static bool isWhitelisted(const llvm::cl::Option& o);
	
	void apply(llvm::cl::Option& o) const;
};

#endif /* fcd__command_line_h */
