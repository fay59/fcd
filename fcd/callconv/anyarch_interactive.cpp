//
// anyarch_interactive.cpp
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

#include "anyarch_interactive.h"
#include "cc_common.h"
#include "metadata.h"
#include "targetinfo.h"

#include <llvm/IR/Constants.h>

#include <iomanip>
#include <iostream>

using namespace llvm;
using namespace std;

namespace
{
	RegisterCallingConvention<CallingConvention_AnyArch_Interactive> registerAnyInteractive;
	
	template<typename T, size_t N>
	constexpr size_t countof(T (&)[N])
	{
		return N;
	}
	
	const char yesNoChars[] = {'y', '1', 'n', '0'};
}

const char* CallingConvention_AnyArch_Interactive::name = "any/interactive";

const char* CallingConvention_AnyArch_Interactive::getName() const
{
	return name;
}

const char* CallingConvention_AnyArch_Interactive::getHelp() const
{
	return "asks about function parameters; needs a system CC";
}

bool CallingConvention_AnyArch_Interactive::matches(TargetInfo &target, Executable &executable) const
{
	// Match nothing.
	return false;
}

bool CallingConvention_AnyArch_Interactive::analyzeFunction(ParameterRegistry &registry, CallInformation &fillOut, llvm::Function &function)
{
	TargetInfo& info = registry.getTargetInfo();
		
	cout << function.getName().str();
	if (auto address = md::getVirtualAddress(function))
	{
		cout << " [" << hex << setfill('0') << setw(info.getPointerSize() * 2) << address->getLimitedValue() << ']';
	}
	cout << " needs register use information." << endl;
	
	char yesNoReturns;
	do
	{
		cout << "Does it have a return value? [y/n] " << flush;
		
		cin.clear(cin.rdstate() & ~ios::failbit);
		if (cin)
		{
			cin >> yesNoReturns;
		}
		else
		{
			yesNoReturns = 'n';
		}
	}
	while (cin.fail() || find(begin(yesNoChars), end(yesNoChars), yesNoReturns) == end(yesNoChars));
	
	unsigned numberOfParameters;
	do
	{
		cout << "How many parameters does it have? " << flush;
		cin.clear(cin.rdstate() & ~ios::failbit);
		if (cin)
		{
			cin >> numberOfParameters;
		}
		else
		{
			numberOfParameters = 0;
		}
	}
	while (cin.fail());
	
	bool returns = yesNoReturns == 'y' || yesNoReturns == '1';
	return hackhack_fillFromParamInfo(function.getContext(), registry, fillOut, returns, numberOfParameters, false);
}
