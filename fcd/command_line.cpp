//
// command_line.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "command_line.h"

#include <llvm/Support/ManagedStatic.h>

#include <cstring>
#include <unordered_set>

using namespace llvm;

namespace
{
	ManagedStatic<std::unordered_set<const cl::Option*>> optWhitelist;
}

bool whitelist::isWhitelisted(const llvm::cl::Option &o)
{
	return o.ArgStr == "help" || o.ArgStr == "version" || optWhitelist->count(&o) != 0;
}

void whitelist::apply(llvm::cl::Option &o) const
{
	optWhitelist->insert(&o);
}
