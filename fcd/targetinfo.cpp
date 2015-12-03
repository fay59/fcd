//
// pass_targetinfo.cpp
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

#include "llvm_warnings.h"
#include "targetinfo.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Constants.h>
#include <llvm/IR/Module.h>
SILENCE_LLVM_WARNINGS_END()

#include <iostream>

using namespace llvm;
using namespace std;

char TargetInfo::ID = 0;

bool TargetInfo::doInitialization(llvm::Module &m)
{
	dl = &m.getDataLayout();
	return ImmutablePass::doInitialization(m);
}

GetElementPtrInst* TargetInfo::getRegister(llvm::Value *registerStruct, const TargetRegisterInfo& info) const
{
	const auto& largest = *largestOverlappingRegister(info);
	
	const TargetRegisterInfo* selected = nullptr;
	for (const auto& targetReg : targetRegisterInfo())
	{
		if (&targetReg == &largest)
		{
			selected = &targetReg;
			break;
		}
	}
	
	if (selected == nullptr)
	{
		return nullptr;
	}
	
	SmallVector<Value*, 4> indices;
	LLVMContext& ctx = registerStruct->getContext();
	IntegerType* int32 = Type::getInt32Ty(ctx);
	IntegerType* int64 = Type::getInt64Ty(ctx);
	CompositeType* currentType = cast<CompositeType>(registerStruct->getType());
	for (unsigned offset : selected->gepOffsets)
	{
		IntegerType* constantType = isa<StructType>(currentType) ? int32 : int64;
		indices.push_back(ConstantInt::get(constantType, offset));
		currentType = dyn_cast<CompositeType>(currentType->getTypeAtIndex(offset));
	}
	return GetElementPtrInst::CreateInBounds(registerStruct, indices);
}

const TargetRegisterInfo* TargetInfo::registerInfo(const Value& value) const
{
	if (auto castInst = dyn_cast<CastInst>(&value))
	{
		return registerInfo(*castInst->getOperand(0));
	}
	if (auto gep = dyn_cast<GetElementPtrInst>(&value))
	{
		return registerInfo(*gep);
	}
	return nullptr;
}

const TargetRegisterInfo* TargetInfo::registerInfo(const GetElementPtrInst &gep) const
{
	// Not reading from a register unless the GEP is from the function's first parameter.
	// This needs to check that the pointer operand of the GEP is an argument of the function that declares it.
	// This is different from checking if the pointer operand of the GEP is an argument of the function that declares
	// the GEP, because consistency between functions is not maintained *during* argument recovery.
	if (const Argument* arg = dyn_cast<Argument>(gep.getPointerOperand()))
	{
		if (arg == arg->getParent()->arg_begin())
		{
			APInt offset(64, 0, false);
			if (gep.accumulateConstantOffset(*dl, offset))
			{
				auto resultType = gep.getResultElementType();
				size_t size = dl->getTypeStoreSize(resultType);
				return registerInfo(offset.getLimitedValue(), size);
			}
		}
	}
	return nullptr;
}

const TargetRegisterInfo* TargetInfo::registerInfo(size_t offset, size_t size) const
{
	assert(targetRegisterInfo().size() > 0);
	// FIXME - do something better than a linear search
	// (especially since targetRegisterInfo() is sorted)
	for (const auto& info : targetRegisterInfo())
	{
		if (info.offset == offset && info.size == size)
		{
			return &info;
		}
		
		if (info.offset > offset)
		{
			break;
		}
	}
	return nullptr;
}

const TargetRegisterInfo* TargetInfo::largestOverlappingRegister(const TargetRegisterInfo& overlapped) const
{
	auto iter = targetRegisterInfo().begin();
	auto end = targetRegisterInfo().end();
	while (iter != end)
	{
		const auto& currentTarget = *iter;
		while (iter->offset < currentTarget.offset + currentTarget.size)
		{
			if (&*iter == &overlapped)
			{
				return &currentTarget;
			}
			iter++;
		}
	}
	return nullptr;
}

TargetInfo* createTargetInfoPass()
{
	return new TargetInfo;
}

INITIALIZE_PASS(TargetInfo, "tginf", "Decompiler Target Info", false, true)
