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
#include "llvm_warnings.h"
#include "pass_targetinfo.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Constants.h>
SILENCE_LLVM_WARNINGS_END()

#include <iomanip>
#include <iostream>

using namespace llvm;
using namespace std;

namespace
{
	template<typename T, size_t N>
	constexpr size_t countof(T (&)[N])
	{
		return N;
	}
	
	const char yesNoChars[] = {'y', '1', 'n', '0'};
	
	bool functionAddress(Function* fn, uint64_t* output)
	{
		if (auto node = fn->getMetadata("fcd.vaddr"))
		if (auto constantMD = dyn_cast<ConstantAsMetadata>(node->getOperand(0)))
		if (auto constantInt = dyn_cast<ConstantInt>(constantMD->getValue()))
		{
			*output = constantInt->getLimitedValue();
			return true;
		}
		return false;
	}
}

const char* CallingConvention_AnyArch_Interactive::getName() const
{
	return "Any/Interactive";
}

bool CallingConvention_AnyArch_Interactive::matches(TargetInfo &target, Executable &executable) const
{
	// Match anything.
	return true;
}

void CallingConvention_AnyArch_Interactive::analyzeFunction(ParameterRegistry &registry, CallInformation &fillOut, llvm::Function &function)
{
	TargetInfo& info = registry.getAnalysis<TargetInfo>();
		
	cout << function.getName().str();
	uint64_t address;
	if (functionAddress(&function, &address))
	{
		cout << " [" << hex << setfill('0') << setw(info.getPointerSize() * 2) << address << ']';
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
	
	LLVMContext& ctx = function.getContext();
	Type* intType = Type::getIntNTy(ctx, info.getPointerSize());
	Type* returnType = yesNoReturns == 'y' || yesNoReturns == '1' ? intType : Type::getVoidTy(ctx);
	vector<Type*> params(numberOfParameters, intType);
	FunctionType* fType = FunctionType::get(returnType, params, false);
	registry.getDefaultCallingConvention()->analyzeFunctionType(registry, fillOut, *fType);
}
