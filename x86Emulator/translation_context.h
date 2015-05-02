//
//  translation_context.h
//  x86Emulator
//
//  Created by Félix on 2015-04-20.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __x86Emulator__translation_context__
#define __x86Emulator__translation_context__

#include <functional>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LLVMContext.h>
#include <memory>
#include <map>
#include <unordered_set>

#include "capstone_wrapper.h"
#include "result_function.h"
#include "x86.h"
#include "x86_emulator.h"

class translation_context
{
	llvm::LLVMContext& context;
	std::unique_ptr<llvm::Module> module;
	capstone cs;
	x86 irgen;
	llvm::legacy::FunctionPassManager identifyJumpTargets;
	
	llvm::Type* voidTy;
	llvm::Type* int8Ty;
	llvm::Type* int16Ty;
	llvm::Type* int32Ty;
	llvm::Type* int64Ty;
	llvm::StructType* x86RegsTy;
	llvm::StructType* x86FlagsTy;
	llvm::StructType* x86ConfigTy;
	llvm::FunctionType* resultFnTy;
	llvm::GlobalVariable* x86Config;
	
	llvm::CastInst* get_pointer(llvm::Value* intptr, size_t size);
	void resolve_intrinsics(result_function& fn, std::unordered_set<uint64_t>& new_labels);
	llvm::Constant* cs_struct(const cs_x86& x86);
	llvm::Function* single_step(llvm::Value* flags, const cs_insn& inst);
	
public:
	translation_context(llvm::LLVMContext& context, const x86_config& config, const std::string& module_name = "");
	~translation_context();
	
	result_function create_function(const std::string& name, uint64_t base_address, const uint8_t* begin, const uint8_t* end);
	
	inline llvm::Module* operator->() { return module.get(); }
	std::unique_ptr<llvm::Module> take();
};

#endif /* defined(__x86Emulator__translation_context__) */
