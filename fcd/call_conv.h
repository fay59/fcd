//
// call_conv.h
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

#ifndef call_conv_hpp
#define call_conv_hpp

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Function.h>
SILENCE_LLVM_WARNINGS_END()

#include <cassert>
#include <memory>

struct ValueInformation
{
	enum StorageClass
	{
		IntegerRegister,
		FloatingPointRegister,
		Stack,
	};
	
	StorageClass type;
	union
	{
		const char* registerName;
		unsigned frameBaseOffset;
	};
	
	ValueInformation(StorageClass regType, const char* registerName)
	: type(regType), registerName(registerName)
	{
		assert(type != Stack);
	}
	
	ValueInformation(StorageClass regType, unsigned frameBaseOffset)
	: type(regType), frameBaseOffset(frameBaseOffset)
	{
		assert(type == Stack);
	}
};

struct CallInformation
{
	llvm::SmallVector<ValueInformation, 1> returnValues;
	llvm::SmallVector<ValueInformation, 6> parameters;
};

class CallingConvention
{
public:
	virtual std::unique_ptr<CallInformation> analyzeFunction(llvm::Function& func) = 0;
	
	virtual ~CallingConvention() = default;
};

#endif /* call_conv_hpp */
