//
// metadata.h
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

#ifndef fcd__metadata_h
#define fcd__metadata_h

#include "params_registry.h"

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Metadata.h>

#include <string>
#include <vector>

namespace md
{
	void ensureFunctionBody(llvm::Function& fn);
	
	std::vector<std::string> getIncludedFiles(llvm::Module& module);
	llvm::ConstantInt* getStackPointerArgument(const llvm::Function& fn);
	llvm::ConstantInt* getVirtualAddress(const llvm::Function& fn);
	unsigned getFunctionVersion(const llvm::Function& fn);
	llvm::Function* getStubTarget(const llvm::Function& fn);
	bool areArgumentsRecoverable(const llvm::Function& fn);
	bool isPrototype(const llvm::Function& fn);
	llvm::MDString* getAssemblyString(const llvm::Function& fn);
	bool isStackFrame(const llvm::AllocaInst& alloca);
	bool isProgramMemory(const llvm::Instruction& value);

	void addIncludedFiles(llvm::Module& module, const std::vector<std::string>& includedFiles);
	void setVirtualAddress(llvm::Function& fn, uint64_t virtualAddress);
	void setStubTarget(llvm::Function& stub, llvm::Function& target);
	void incrementFunctionVersion(llvm::Function& fn);
	void setArgumentsRecoverable(llvm::Function& fn, bool recoverable = true);
	void setStackPointerArgument(llvm::Function& fn, unsigned argIndex);
	void removeStackPointerArgument(llvm::Function& fn);
	void setAssemblyString(llvm::Function& fn, llvm::StringRef assembly);
	void setStackFrame(llvm::AllocaInst& alloca);
	void setProgramMemory(llvm::Instruction& value, bool isProgramMemory = true);
	
	void copy(const llvm::Function& from, llvm::Function& to);
	
	bool isRegisterStruct(const llvm::Value& value);
	void setRegisterStruct(llvm::AllocaInst& alloca, bool registerStruct = true);
	
	void setRecoveredReturnFieldNames(llvm::Module& module, llvm::StructType& returnType, const CallInformation& callInfo);
	llvm::StringRef getRecoveredReturnFieldName(llvm::Module& module, llvm::StructType& returnType, unsigned i);
}

#endif /* fcd__metadata_h */
