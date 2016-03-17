//
// anyarch_noargs.cpp
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

#include "anyarch_noargs.h"

namespace
{
	RegisterCallingConvention<CallingConvention_AnyArch_NoArgs> registerAnyNoArgs;
}

const char* CallingConvention_AnyArch_NoArgs::name = "anyarch/noargs";

const char* CallingConvention_AnyArch_NoArgs::getName() const
{
	return name;
}

const char* CallingConvention_AnyArch_NoArgs::getHelp() const
{
	return "debug only; pretends that functions don't have arguments";
}

bool CallingConvention_AnyArch_NoArgs::matches(TargetInfo &target, Executable &executable) const
{
	// Match nothing.
	return false;
}

bool CallingConvention_AnyArch_NoArgs::analyzeFunction(ParameterRegistry &registry, CallInformation &fillOut, llvm::Function &func)
{
	return true;
}

bool CallingConvention_AnyArch_NoArgs::analyzeFunctionType(ParameterRegistry &registry, CallInformation &fillOut, llvm::FunctionType &type)
{
	return true;
}

bool CallingConvention_AnyArch_NoArgs::analyzeCallSite(ParameterRegistry &registry, CallInformation &fillOut, llvm::CallSite cs)
{
	return true;
}
