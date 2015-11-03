//
// x86_64_systemv.cpp
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

// About the x86_64 SystemV calling convention:
// http://x86-64.org/documentation/abi.pdf pp 20-22
// In short, for arguments:
// - Aggregates are passed in registers, unless one of the fields is a floating-point field, in which case it goes to
//		memory; or unless not enough integer registers are available, in which case it also goes to the stack.
// - Integral arguments are passed in rdi-rsi-rdx-rcx-r8-r9.
// - Floating-point arguments are passed in [xyz]mm0-[xyz]mm7
// - Anything else/left remaining goes to the stack.
// For return values:
// - Integral values go to rax-rdx.
// - Floating-point values go to xmm0-xmm1.
// - Large return values may be written to *rdi, and rax will contain rdi (in which case it's indistinguishible from
//		a function accepting the output destination as a first parameter).
// The relative parameter order of values of different classes is not preserved.

#include "cc_common.h"
#include "x86_64_systemv.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/PatternMatch.h>
#include "MemorySSA.h"
SILENCE_LLVM_WARNINGS_END()

#include <unordered_map>

using namespace llvm;
using namespace llvm::PatternMatch;
using namespace std;

namespace
{
	RegisterCallingConvention<CallingConvention_x86_64_systemv> registerSysV;
	
	const char* returnRegisters[] = {"rax", "rdx"};
	const char* parameterRegisters[] = { "rdi", "rsi", "rdx", "rcx", "r8", "r9" };
	
	typedef void (CallInformation::*AddParameter)(ValueInformation&&);
	
	// only handles integer types
	bool addEntriesForType(TargetInfo& targetInfo, CallInformation& info, AddParameter addParam, Type* type, const char**& regIter, const char** end, size_t* spOffset = nullptr)
	{
		unsigned pointerSize = targetInfo.getPointerSize();
		if (isa<PointerType>(type))
		{
			type = IntegerType::get(type->getContext(), pointerSize);
		}
		
		if (auto intType = dyn_cast<IntegerType>(type))
		{
			unsigned bitSize = intType->getIntegerBitWidth();
			while (regIter != end && bitSize != 0)
			{
				(info.*addParam)(ValueInformation(ValueInformation::IntegerRegister, targetInfo.registerNamed(*regIter)));
				regIter++;
				bitSize -= min<unsigned>(bitSize, 64);
			}
			
			if (spOffset != nullptr)
			{
				while (bitSize != 0)
				{
					(info.*addParam)(ValueInformation(ValueInformation::Stack, *spOffset));
					*spOffset += 8;
					bitSize -= 64;
				}
			}
			return bitSize == 0;
		}
		
		return type == Type::getVoidTy(type->getContext());
	}
}

const char* CallingConvention_x86_64_systemv::name = "x86_64/SystemV";

bool CallingConvention_x86_64_systemv::matches(TargetInfo &target, Executable &executable) const
{
	const char arch[] = "x86";
	const char exe[] = "ELF 64";
	return strncmp(target.targetName().c_str(), arch, sizeof arch - 1) == 0
		&& strncmp(executable.getExecutableType().c_str(), exe, sizeof exe - 1) == 0;
}

const char* CallingConvention_x86_64_systemv::getName() const
{
	return name;
}

bool CallingConvention_x86_64_systemv::analyzeFunction(ParameterRegistry &registry, CallInformation &callInfo, llvm::Function &function)
{
	// TODO: Look at called functions to find hidden parameters/return values
	
	if (function.isDeclaration())
	{
		return false;
	}
	
	TargetInfo& targetInfo = registry.getAnalysis<TargetInfo>();
	
	// We always need rsp, rbp and rip.
	callInfo.addParameter(ValueInformation::IntegerRegister, targetInfo.registerNamed("rip"));
	callInfo.addParameter(ValueInformation::IntegerRegister, targetInfo.registerNamed("rbp"));
	callInfo.addParameter(ValueInformation::IntegerRegister, targetInfo.registerNamed("rsp"));
	
	// Identify register GEPs.
	// (assume x86 regs as first parameter)
	assert(function.arg_size() == 1);
	Argument* regs = function.arg_begin();
	auto pointerType = dyn_cast<PointerType>(regs->getType());
	assert(pointerType != nullptr && pointerType->getTypeAtIndex(int(0))->getStructName() == "struct.x86_regs");
	
	unordered_multimap<const TargetRegisterInfo*, GetElementPtrInst*> geps;
	for (auto& use : regs->uses())
	{
		if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(use.getUser()))
		if (const TargetRegisterInfo* regName = targetInfo.registerInfo(*gep))
		{
			geps.insert({regName, gep});
		}
	}
	
	// Look at temporary registers that are read before they are written
	MemorySSA& mssa = *registry.getMemorySSA(function);
	for (const char* name : parameterRegisters)
	{
		const TargetRegisterInfo* smallReg = targetInfo.registerNamed(name);
		const TargetRegisterInfo* regInfo = targetInfo.largestOverlappingRegister(*smallReg);
		auto range = geps.equal_range(regInfo);
		for (auto iter = range.first; iter != range.second; ++iter)
		{
			for (auto& use : iter->second->uses())
			{
				if (auto load = dyn_cast<LoadInst>(use.getUser()))
				{
					MemoryAccess* parent = mssa.getMemoryAccess(load)->getDefiningAccess();
					if (mssa.isLiveOnEntryDef(parent))
					{
						// register argument!
						callInfo.addParameter(ValueInformation::IntegerRegister, regInfo);
					}
				}
			}
		}
	}
	
	// Does the function refer to values at an offset above the initial rsp value?
	// Assume that rsp is known to be preserved.
	auto spRange = geps.equal_range(targetInfo.getStackPointer());
	for (auto iter = spRange.first; iter != spRange.second; ++iter)
	{
		auto* gep = iter->second;
		// Find all uses of reference to sp register
		for (auto& use : gep->uses())
		{
			if (auto load = dyn_cast<LoadInst>(use.getUser()))
			{
				// Find uses above +8 (since +0 is the return address)
				for (auto& use : load->uses())
				{
					ConstantInt* offset = nullptr;
					if (match(use.get(), m_Add(m_Value(), m_ConstantInt(offset))))
					{
						make_signed<decltype(offset->getLimitedValue())>::type intOffset = offset->getLimitedValue();
						if (intOffset > 8)
						{
							// memory argument!
							callInfo.addParameter(ValueInformation::Stack, intOffset);
						}
					}
				}
			}
		}
	}
	
	// Are we using return registers?
	vector<const TargetRegisterInfo*> usedReturns;
	usedReturns.reserve(2);
	
	for (const char* name : returnRegisters)
	{
		const TargetRegisterInfo* regInfo = targetInfo.registerNamed(name);
		auto range = geps.equal_range(regInfo);
		for (auto iter = range.first; iter != range.second; ++iter)
		{
			for (auto& use : iter->second->uses())
			{
				if (isa<StoreInst>(use.getUser()))
				{
					usedReturns.push_back(regInfo);
				}
			}
		}
	}
	
	for (const TargetRegisterInfo* reg : ipaFindUsedReturns(registry, function, usedReturns))
	{
		// return value!
		callInfo.addReturn(ValueInformation::IntegerRegister, reg);
	}
	
	return true;
}

bool CallingConvention_x86_64_systemv::analyzeFunctionType(ParameterRegistry& registry, CallInformation& fillOut, FunctionType& type)
{
	TargetInfo& targetInfo = registry.getAnalysis<TargetInfo>();
	auto iter = begin(returnRegisters);
	auto addReturn = &CallInformation::addReturn<ValueInformation>;
	if (!addEntriesForType(targetInfo, fillOut, addReturn, type.getReturnType(), iter, end(returnRegisters)))
	{
		return false;
	}
	
	size_t spOffset = 0;
	iter = begin(parameterRegisters);
	auto addParam = &CallInformation::addParameter<ValueInformation>;
	for (Type* t : type.params())
	{
		if (!addEntriesForType(targetInfo, fillOut, addParam, t, iter, end(parameterRegisters), &spOffset))
		{
			return false;
		}
	}
	
	return true;
}
