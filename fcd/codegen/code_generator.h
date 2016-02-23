//
// code_generator.h
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

#ifndef code_generator_h
#define code_generator_h

#include "capstone_wrapper.h"
#include "llvm_warnings.h"
#include "not_null.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Constants.h>
#include <llvm/IR/Module.h>
#include <llvm/Transforms/Utils/Cloning.h>
SILENCE_LLVM_WARNINGS_END()

#include <cstdint>
#include <memory>
#include <vector>

class CodeGenerator
{
	llvm::LLVMContext& ctx;
	std::unique_ptr<llvm::Module> generatorModule;
	std::vector<llvm::Function*> functionByOpcode;
	
protected:
	CodeGenerator(llvm::LLVMContext& ctx);
	
	llvm::Function* getFunction(const char* name)
	{
		return module().getFunction(name);
	}
	
	llvm::LLVMContext& context() { return ctx; }
	llvm::Module& module() { return *generatorModule; }
	bool initGenerator(const char* begin, const char* end);
	std::vector<llvm::Function*>& getFunctionMap() { return functionByOpcode; }
	
	virtual bool init() = 0;
	
public:
	virtual ~CodeGenerator() = default;
	static std::unique_ptr<CodeGenerator> x86(llvm::LLVMContext& ctx);
	
	llvm::Function* implementationFor(unsigned index)
	{
		return functionByOpcode.at(index);
	}
	
	virtual llvm::Function* implementationForPrologue() = 0;
	virtual llvm::StructType* getRegisterTy() = 0;
	virtual llvm::StructType* getFlagsTy() = 0;
	virtual llvm::StructType* getConfigTy() = 0;
	virtual llvm::ArrayRef<llvm::Value*> getIpOffset() = 0;
	virtual llvm::Constant* constantForDetail(const cs_detail& detail) = 0;
};

#endif /* code_generator_hpp */
