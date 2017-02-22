//
// targetinfo.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__targetinfo_h
#define fcd__targetinfo_h


#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Instructions.h>

#include <limits>
#include <memory>
#include <string>
#include <vector>

struct TargetRegisterInfo
{
	size_t offset;
	size_t size;
	llvm::SmallVector<unsigned, 4> gepOffsets;
	std::string name;
	unsigned registerId;
};

class TargetInfo
{
	std::string name;
	size_t spIndex;
	const std::vector<TargetRegisterInfo>* targetRegInfo;
	const llvm::DataLayout* dl;
	
	TargetInfo()
	: spIndex(std::numeric_limits<size_t>::max()), targetRegInfo(nullptr), dl(nullptr)
	{
	}

public:
	static std::unique_ptr<TargetInfo> getTargetInfo(const llvm::Module& module);
	
	inline const std::vector<TargetRegisterInfo>& targetRegisterInfo() const
	{
		assert(targetRegInfo != nullptr);
		return *targetRegInfo;
	}
	
	inline void setTargetRegisterInfo(const std::vector<TargetRegisterInfo>& targetRegInfos)
	{
		this->targetRegInfo = &targetRegInfos;
	}
	
	inline std::string& targetName()
	{
		return name;
	}
	
	inline const std::string& targetName() const
	{
		return name;
	}
	
	unsigned getPointerSize() const
	{
		return dl->getPointerSize();
	}
	
	inline const TargetRegisterInfo* registerNamed(const char* regname) const
	{
		for (const auto& regInfo : targetRegisterInfo())
		{
			if (regInfo.name == regname)
			{
				return &regInfo;
			}
		}
		return nullptr;
	}
	
	llvm::GetElementPtrInst* getRegister(llvm::Value* registerStruct, const TargetRegisterInfo& info) const;
	
	const TargetRegisterInfo* registerInfo(unsigned registerId) const;
	const TargetRegisterInfo* registerInfo(const llvm::Value& value) const;
	const TargetRegisterInfo* registerInfo(const llvm::GetElementPtrInst& value) const;
	const TargetRegisterInfo* registerInfo(size_t offset, size_t size) const;
	const TargetRegisterInfo& largestOverlappingRegister(const TargetRegisterInfo& overlapped) const;
	
	inline void setStackPointer(const TargetRegisterInfo& targetReg)
	{
		for (size_t i = 0; i < targetRegisterInfo().size(); i++)
		{
			const auto& thisReg = targetRegisterInfo()[i];
			if (targetReg.offset == thisReg.offset && targetReg.size == thisReg.size)
			{
				spIndex = i;
				break;
			}
		}
	}
	
	inline const TargetRegisterInfo* getStackPointer() const
	{
		if (spIndex < targetRegisterInfo().size())
		{
			return &targetRegisterInfo()[spIndex];
		}
		return nullptr;
	}
};

#endif /* fcd__targetinfo_h */
