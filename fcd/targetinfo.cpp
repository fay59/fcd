//
// pass_targetinfo.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "metadata.h"
#include "targetinfo.h"
#include "x86_register_map.h"

#include <llvm/ADT/Triple.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Module.h>

#include <iostream>

using namespace llvm;
using namespace std;

unique_ptr<TargetInfo> TargetInfo::getTargetInfo(const Module& module)
{
	Triple triple(module.getTargetTriple());
	auto arch = triple.getArch();
	if (arch == Triple::x86_64)
	{
		auto info = new TargetInfo;
		info->dl = &module.getDataLayout();
		x86TargetInfo(info);
		return unique_ptr<TargetInfo>(info);
	}
	return nullptr;
}

Instruction* TargetInfo::getRegister(llvm::Value *registerStruct, const TargetRegisterInfo& info, Instruction& insertionPoint) const
{
	const auto& largest = largestOverlappingRegister(info);
	
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
	
	LLVMContext& ctx = registerStruct->getContext();
	IntegerType* int32 = Type::getInt32Ty(ctx);
	IntegerType* int64 = Type::getInt64Ty(ctx);
	
	SmallVector<Value*, 4> indices { ConstantInt::get(int64, 0) };
	CompositeType* currentType = cast<CompositeType>(cast<PointerType>(registerStruct->getType())->getElementType());
	for (unsigned offset : selected->gepOffsets)
	{
		IntegerType* constantType = isa<StructType>(currentType) ? int32 : int64;
		indices.push_back(ConstantInt::get(constantType, offset));
		currentType = dyn_cast<CompositeType>(currentType->getTypeAtIndex(offset));
	}
	
	Instruction* result = GetElementPtrInst::CreateInBounds(registerStruct, indices, "", &insertionPoint);
	if (info.subOffset != 0)
	{
		auto intptrTy = dl->getIntPtrType(ctx);
		auto asInt = CastInst::CreateBitOrPointerCast(result, intptrTy, "", &insertionPoint);
		auto added = BinaryOperator::CreateAdd(asInt, ConstantInt::get(intptrTy, info.subOffset), "", &insertionPoint);
		auto resultType = Type::getIntNTy(ctx, static_cast<unsigned>(info.size * CHAR_BIT));
		result = CastInst::CreateBitOrPointerCast(added, resultType, "", &insertionPoint);
	}
	return result;
}

const TargetRegisterInfo* TargetInfo::registerInfo(unsigned int registerId) const
{
	for (const auto& info : targetRegisterInfo())
	{
		if (info.registerId == registerId)
		{
			return &info;
		}
	}
	return nullptr;
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
	if (md::isRegisterStruct(*gep.getPointerOperand()))
	{
		APInt offset(64, 0, false);
		if (gep.accumulateConstantOffset(*dl, offset))
		{
			auto resultType = gep.getResultElementType();
			size_t size = dl->getTypeStoreSize(resultType);
			return registerInfo(offset.getLimitedValue(), size);
		}
	}
	return nullptr;
}

const TargetRegisterInfo* TargetInfo::registerInfo(size_t offset, size_t size) const
{
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

const TargetRegisterInfo& TargetInfo::largestOverlappingRegister(const TargetRegisterInfo& overlapped) const
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
				return currentTarget;
			}
			iter++;
		}
	}
	llvm_unreachable("Missing register in largestOverlappingRegister?!");
}
