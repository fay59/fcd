//
// call_conv.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "call_conv.h"

#include <llvm/Support/ManagedStatic.h>

#include <map>

using namespace llvm;
using namespace std;

namespace
{
	ManagedStatic<map<string, CallingConvention*>> ccRegistry;
}

bool CallingConvention::registerCallingConvention(CallingConvention* cc)
{
	return ccRegistry->insert(make_pair(cc->getName(), cc)).second;
}

CallingConvention* CallingConvention::getCallingConvention(const std::string &name)
{
	auto iter = ccRegistry->find(name);
	return iter == ccRegistry->end() ? nullptr : iter->second;
}

CallingConvention* CallingConvention::getMatchingCallingConvention(TargetInfo &target, Executable &executable)
{
	for (const auto& pair : *ccRegistry)
	{
		if (pair.second->matches(target, executable))
		{
			return pair.second;
		}
	}
	return nullptr;
}

vector<CallingConvention*> CallingConvention::getCallingConventions()
{
	vector<CallingConvention*> result;
	for (const auto& pair : *ccRegistry)
	{
		result.push_back(pair.second);
	}
	return result;
}

const char* CallingConvention::getHelp() const
{
	return "";
}

void CallingConvention::getAnalysisUsage(AnalysisUsage& au) const
{
}

bool CallingConvention::analyzeFunction(ParameterRegistry &registry, CallInformation &fillOut, Function &func)
{
	return false;
}

bool CallingConvention::analyzeCallSite(ParameterRegistry &registry, CallInformation &fillOut, CallSite cs)
{
	return false;
}

bool CallingConvention::analyzeFunctionType(ParameterRegistry& registry, CallInformation& fillOut, FunctionType& type)
{
	return false;
}

bool CallingConvention::matches(TargetInfo &target, Executable &executable) const
{
	// By default, calling conventions don't match anything but can still be used by name.
	return false;
}
