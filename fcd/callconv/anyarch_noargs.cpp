//
// anyarch_noargs.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "anyarch_noargs.h"

namespace
{
	RegisterCallingConvention<CallingConvention_AnyArch_NoArgs> registerAnyNoArgs;
}

const char* CallingConvention_AnyArch_NoArgs::name = "any/noargs";

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
