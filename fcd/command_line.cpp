//
// command_line.cpp
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

#include "command_line.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/ManagedStatic.h>
SILENCE_LLVM_WARNINGS_END()

#include <cstring>
#include <unordered_set>

using namespace llvm;

namespace
{
	ManagedStatic<std::unordered_set<const cl::Option*>> optWhitelist;
}

bool whitelist::isWhitelisted(const llvm::cl::Option &o)
{
	return strncmp(o.ArgStr, "help", 4) == 0 || strcmp(o.ArgStr, "version") == 0 || optWhitelist->count(&o) != 0;
}

void whitelist::apply(llvm::cl::Option &o) const
{
	optWhitelist->insert(&o);
}
