//
// call_conv.cpp
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

#include "call_conv.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/ManagedStatic.h>
SILENCE_LLVM_WARNINGS_END()

#include <unordered_map>

using namespace llvm;
using namespace std;

namespace
{
	ManagedStatic<unordered_map<string, CallingConvention*>> ccRegistry;
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
