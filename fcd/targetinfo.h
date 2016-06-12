//
// targetinfo.h
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

#ifndef fcd__targetinfo_h
#define fcd__targetinfo_h


#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Instructions.h>

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
	: spIndex(0xffffffff), targetRegInfo(nullptr), dl(nullptr)
	{
	}

public:
	static std::unique_ptr<TargetInfo> getTargetInfo(const llvm::Module& module);
	
	inline const std::vector<TargetRegisterInfo>& targetRegisterInfo() const
	{
		assert(targetRegInfo != nullptr);
		return *targetRegInfo;
	}
	
	inline void setTargetRegisterInfo(const std::vector<TargetRegisterInfo>& targetRegInfo)
	{
		this->targetRegInfo = &targetRegInfo;
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
	
	inline const TargetRegisterInfo* registerNamed(const char* name) const
	{
		for (const auto& regInfo : targetRegisterInfo())
		{
			if (regInfo.name == name)
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
