//
// code_generator.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef code_generator_h
#define code_generator_h

#include "capstone_wrapper.h"
#include "not_null.h"
#include "translation_maps.h"

#include <llvm/IR/Constants.h>
#include <llvm/IR/Module.h>
#include <llvm/Transforms/Utils/Cloning.h>

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
	virtual void getModuleLevelValueChanges(llvm::ValueToValueMapTy& map, llvm::Module& targetModule) = 0;
	virtual void resolveIntrinsics(llvm::Function& targetFunction, AddressToFunction& funcMap, AddressToBlock& blockMap) = 0;
	
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
	
	void inlineFunction(llvm::Function *target, llvm::Function *toInline, llvm::ArrayRef<llvm::Value *> parameters, AddressToFunction& funcMap, AddressToBlock& blockMap, uint64_t nextAddress);
};

#endif /* code_generator_hpp */
