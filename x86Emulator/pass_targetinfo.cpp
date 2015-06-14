//
//  pass_targetinfo.cpp
//  x86Emulator
//
//  Created by Félix on 2015-06-12.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#include "pass_targetinfo.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Constants.h>
#include <llvm/IR/Module.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

char TargetInfo::ID = 0;

bool TargetInfo::doInitialization(llvm::Module &m)
{
	dl = &m.getDataLayout();
	return ImmutablePass::doInitialization(m);
}

GetElementPtrInst* TargetInfo::getRegister(llvm::Value *registerStruct, const char *name) const
{
	name = largestOverlappingRegister(name);
	
	const TargetRegisterInfo* selected = nullptr;
	for (const auto& info : targetRegisterInfo())
	{
		if (info.name.c_str() == name)
		{
			selected = &info;
			break;
		}
	}
	
	if (selected == nullptr)
	{
		return nullptr;
	}
	
	SmallVector<Value*, 4> indices;
	IntegerType* int64 = Type::getInt64Ty(registerStruct->getContext());
	for (unsigned offset : selected->gepOffsets)
	{
		indices.push_back(ConstantInt::get(int64, offset));
	}
	return GetElementPtrInst::CreateInBounds(registerStruct, indices);
}

const char* TargetInfo::registerName(const Value& value) const
{
	if (auto castInst = dyn_cast<CastInst>(&value))
	{
		return registerName(*castInst->getOperand(0));
	}
	if (auto gep = dyn_cast<GetElementPtrInst>(&value))
	{
		return registerName(*gep);
	}
	return nullptr;
}

const char* TargetInfo::registerName(const GetElementPtrInst &gep) const
{
	// not reading from a register unless the GEP is from the function's first parameter
	const Function* fn = gep.getParent()->getParent();
	if (gep.getOperand(0) != fn->arg_begin())
	{
		return nullptr;
	}
	
	APInt offset(64, 0, false);
	if (gep.accumulateConstantOffset(*dl, offset))
	{
		auto resultType = gep.getResultElementType();
		size_t size = dl->getTypeStoreSize(resultType);
		return registerName(offset.getLimitedValue(), size);
	}
	return nullptr;
}

const char* TargetInfo::registerName(size_t offset, size_t size) const
{
	assert(targetRegisterInfo().size() > 0);
	// FIXME - do something better than a linear search
	// (especially since targetRegisterInfo() is sorted)
	for (const auto& info : targetRegisterInfo())
	{
		if (info.offset == offset && info.size == size)
		{
			return info.name.c_str();
		}
		
		if (info.offset > offset)
		{
			break;
		}
	}
	return nullptr;
}

const char* TargetInfo::largestOverlappingRegister(const char *overlapped) const
{
	if (overlapped == nullptr)
	{
		return nullptr;
	}
	
	auto iter = targetRegisterInfo().begin();
	auto end = targetRegisterInfo().end();
	while (iter != end)
	{
		const auto& currentTarget = *iter;
		while (iter->offset < currentTarget.offset + currentTarget.size)
		{
			if (iter->name.c_str() == overlapped)
			{
				return currentTarget.name.c_str();
			}
			iter++;
		}
	}
	return nullptr;
}

const char* TargetInfo::keyName(const char *name) const
{
	if (name == nullptr)
	{
		return nullptr;
	}
	
	for (const auto& info : targetRegisterInfo())
	{
		if (info.name == name)
		{
			return info.name.c_str();
		}
	}
	return nullptr;
}

TargetInfo* createTargetInfoPass()
{
	return new TargetInfo;
}

INITIALIZE_PASS(TargetInfo, "tginf", "Decompiler Target Info", false, true)
