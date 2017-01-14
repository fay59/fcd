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
#include "metadata.h"
#include "x86_64_systemv.h"

#include <llvm/IR/PatternMatch.h>
#include <llvm/Transforms/Utils/MemorySSA.h>

#include <unordered_map>

using namespace llvm;
using namespace llvm::PatternMatch;
using namespace std;

namespace
{
	RegisterCallingConvention<CallingConvention_x86_64_systemv> registerSysV;
	
	const char* parameterRegisters[] = { "rdi", "rsi", "rdx", "rcx", "r8", "r9" };
	const char* returnRegisters[] = {"rax", "rdx"};
	
	inline const char** registerPosition(const TargetRegisterInfo& reg, const char** begin, const char** end)
	{
		return find(begin, end, reg.name);
	}
	
	inline bool isParameterRegister(const TargetRegisterInfo& reg)
	{
		return registerPosition(reg, begin(parameterRegisters), end(parameterRegisters)) != end(parameterRegisters);
	}
	
	inline bool isReturnRegister(const TargetRegisterInfo& reg)
	{
		return registerPosition(reg, begin(returnRegisters), end(returnRegisters)) != end(returnRegisters);
	}
	
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
					bitSize -= min<unsigned>(bitSize, 64);
				}
			}
			return bitSize == 0;
		}
		
		return type == Type::getVoidTy(type->getContext());
	}
	
	void identifyParameterCandidates(TargetInfo& target, MemorySSA& mssa, MemoryAccess* access, CallInformation& fillOut)
	{
		// Look for values that are written but not used by the caller (parameters).
		// MemorySSA chains memory uses and memory defs. Walk back from the call until the previous call, or to liveOnEntry.
		// Registers in the parameter set that are written to before the function call are parameters for sure.
		// Stack values that are written before a function must also be analyzed post-call to make sure that they're not
		// read again before we can determine with certainty that they're parameters.
		while (!mssa.isLiveOnEntryDef(access))
		{
			if (isa<MemoryPhi>(access))
			{
				// too hard, give up
				break;
			}
			
			auto useOrDef = cast<MemoryUseOrDef>(access);
			Instruction* memoryInst = useOrDef->getMemoryInst();
			if (isa<CallInst>(memoryInst))
			{
				break;
			}
			
			auto def = cast<MemoryDef>(useOrDef);
			// TODO: this check is only *almost* good. The right thing to do would be to make sure that the only
			// accesses reaching from this def are other defs (with a call ending the chain). However, just checking
			// that there is a single use is much faster, and probably good enough.
			if (def->hasOneUse())
			{
				if (auto store = dyn_cast<StoreInst>(memoryInst))
				{
					auto& pointer = *store->getPointerOperand();
					if (const TargetRegisterInfo* info = target.registerInfo(pointer))
					{
						// this could be a parameter register
						if (isParameterRegister(*info))
						{
							auto range = fillOut.parameters();
							auto position = lower_bound(range.begin(), range.end(), info, [](const ValueInformation& that, const TargetRegisterInfo* i)
							{
								if (that.type == ValueInformation::IntegerRegister)
								{
									auto thatName = registerPosition(*that.registerInfo, begin(parameterRegisters), end(parameterRegisters));
									auto iName = registerPosition(*i, begin(parameterRegisters), end(parameterRegisters));
									return thatName < iName;
								}
								return false;
							});
							
							// TODO: add registers in sequence up to this register
							// (for instance, if we see a use for `rdi` and `rdx`, add `rsi`)
							
							if (position == range.end() || position->registerInfo != info)
							{
								fillOut.insertParameter(position, ValueInformation::IntegerRegister, info);
							}
						}
					}
					else if (md::isProgramMemory(*store))
					{
						// this could be a stack register
						Value* origin = nullptr;
						ConstantInt* offset = nullptr;
						if (match(&pointer, m_BitCast(m_Add(m_Value(origin), m_ConstantInt(offset)))))
						if (const TargetRegisterInfo* rsp = target.registerInfo(*origin))
						if (rsp->name == "rsp")
						{
							// stack parameter
							auto range = fillOut.parameters();
							auto position = lower_bound(range.begin(), range.end(), offset->getLimitedValue(), [](const ValueInformation& that, uint64_t offset)
							{
								return that.type < ValueInformation::Stack || that.frameBaseOffset < offset;
							});
							
							// TODO: add/extend values up to this stack offset.
							// If we see a parameter at +0 and a parameter at +16, then we have missing values.
							
							if (position == range.end() || position->registerInfo != info)
							{
								fillOut.insertParameter(position, ValueInformation::IntegerRegister, info);
							}
						}
					}
				}
				else
				{
					// if it's not a call and it's not a store, then what is it?
					assert(false);
				}
			}
			
			access = useOrDef->getDefiningAccess();
		}
	}
	
	void identifyReturnCandidates(TargetInfo& target, MemorySSA& mssa, MemoryAccess* access, CallInformation& fillOut)
	{
		for (User* user : access->users())
		{
			if (auto memPhi = dyn_cast<MemoryPhi>(user))
			{
				identifyReturnCandidates(target, mssa, memPhi, fillOut);
			}
			else if (auto memUse = dyn_cast<MemoryUse>(user))
			{
				if (auto load = dyn_cast<LoadInst>(memUse->getMemoryInst()))
				if (const TargetRegisterInfo* info = target.registerInfo(*load->getPointerOperand()))
				if (isReturnRegister(*info))
				{
					auto range = fillOut.returns();
					auto position = lower_bound(range.begin(), range.end(), info, [](const ValueInformation& that, const TargetRegisterInfo* i)
					{
						if (that.type == ValueInformation::IntegerRegister)
						{
							auto thatName = registerPosition(*that.registerInfo, begin(parameterRegisters), end(parameterRegisters));
							auto iName = registerPosition(*i, begin(parameterRegisters), end(parameterRegisters));
							return thatName < iName;
						}
						return false;
					});
					
					// TODO: add registers in sequence up to this register
					// (for instance, if we see a use for `rdx`, there should be an `rax` somewhere)
					if (position == range.end() || position->registerInfo != info)
					{
						fillOut.insertReturn(position, ValueInformation::IntegerRegister, info);
					}
				}
			}
		}
	}
}

const char* CallingConvention_x86_64_systemv::name = "x86_64/sysv";

const char* CallingConvention_x86_64_systemv::getHelp() const
{
	return "x86_64 SystemV ABI system calling convention";
}

bool CallingConvention_x86_64_systemv::matches(TargetInfo &target, Executable &executable) const
{
	string triple = executable.getTargetTriple();
	string::size_type firstDash = triple.find('-');
	string::size_type secondDash = triple.find('-', firstDash + 1);
	string::size_type nextDash = triple.find('-', secondDash + 1);
	string arch = triple.substr(0, firstDash);
	string os = triple.substr(secondDash + 1, nextDash);
	if (arch.compare(0, 3, "x86") == 0)
	{
		return os.compare(0, 6, "macosx") == 0 || executable.getExecutableType().compare(0, 3, "ELF") == 0;
	}
	return false;
}

const char* CallingConvention_x86_64_systemv::getName() const
{
	return name;
}

bool CallingConvention_x86_64_systemv::analyzeFunction(ParameterRegistry &registry, CallInformation &callInfo, Function &function)
{
	// TODO: Look at called functions to find hidden parameters/return values
	
	if (md::isPrototype(function))
	{
		return false;
	}
	
	TargetInfo& targetInfo = registry.getTargetInfo();
	
	// We always need rip and rsp.
	callInfo.addParameter(ValueInformation::IntegerRegister, targetInfo.registerNamed("rip"));
	callInfo.addParameter(ValueInformation::IntegerRegister, targetInfo.registerNamed("rsp"));
	
	// Identify register GEPs.
	// (assume x86 regs as first parameter)
	assert(function.arg_size() == 1);
	auto regs = static_cast<Argument*>(function.arg_begin());
	auto pointerType = dyn_cast<PointerType>(regs->getType());
	assert(pointerType != nullptr && pointerType->getTypeAtIndex(int(0))->getStructName() == "struct.x86_regs");
	(void) pointerType;
	
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
		const TargetRegisterInfo& regInfo = targetInfo.largestOverlappingRegister(*smallReg);
		auto range = geps.equal_range(&regInfo);
		
		vector<Instruction*> addresses;
		for (auto iter = range.first; iter != range.second; ++iter)
		{
			addresses.push_back(iter->second);
		}
		
		for (size_t i = 0; i < addresses.size(); ++i)
		{
			Instruction* addressInst = addresses[i];
			for (auto& use : addressInst->uses())
			{
				if (auto load = dyn_cast<LoadInst>(use.getUser()))
				{
					MemoryAccess* parent = cast<MemoryUse>(mssa.getMemoryAccess(load))->getDefiningAccess();
					if (mssa.isLiveOnEntryDef(parent))
					{
						// register argument!
						callInfo.addParameter(ValueInformation::IntegerRegister, &regInfo);
					}
				}
				else if (auto cast = dyn_cast<CastInst>(use.getUser()))
				{
					if (cast->getType()->isPointerTy())
					{
						addresses.push_back(cast);
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
						auto intOffset = static_cast<int64_t>(offset->getLimitedValue());
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
			bool hasStore = any_of(iter->second->use_begin(), iter->second->use_end(), [](Use& use)
			{
				return isa<StoreInst>(use.getUser());
			});
			
			if (hasStore)
			{
				usedReturns.push_back(regInfo);
				break;
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
	TargetInfo& targetInfo = registry.getTargetInfo();
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

bool CallingConvention_x86_64_systemv::analyzeCallSite(ParameterRegistry &registry, CallInformation &fillOut, CallSite cs)
{
	fillOut.clear();
	TargetInfo& targetInfo = registry.getTargetInfo();
	
	Instruction& inst = *cs.getInstruction();
	Function& caller = *inst.getParent()->getParent();
	MemorySSA& mssa = *registry.getMemorySSA(caller);
	MemoryDef* thisDef = cast<MemoryDef>(mssa.getMemoryAccess(&inst));
	
	identifyParameterCandidates(targetInfo, mssa, thisDef->getDefiningAccess(), fillOut);
	identifyReturnCandidates(targetInfo, mssa, thisDef, fillOut);
	return true;
}
