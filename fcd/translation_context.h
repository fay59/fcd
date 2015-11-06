//
// translation_context.h
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

#ifndef __x86Emulator__translation_context__
#define __x86Emulator__translation_context__

#include "capstone_wrapper.h"
#include "llvm_warnings.h"
#include "pass_targetinfo.h"
#include "result_function.h"
#include "x86_emulator.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LLVMContext.h>
#include "x86.h"
SILENCE_LLVM_WARNINGS_END()

#include <memory>
#include <unordered_map>
#include <unordered_set>

class translation_context
{
	llvm::LLVMContext& context;
	std::unique_ptr<llvm::Module> module;
	std::unordered_map<uint64_t, std::string> aliases;
	std::unique_ptr<capstone> cs;
	x86 irgen;
	llvm::legacy::FunctionPassManager clarifyInstruction;
	
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
	
	llvm::CastInst& get_pointer(llvm::Value* intptr, size_t size);
	void resolve_intrinsics(result_function& fn, std::unordered_set<uint64_t>& new_labels);
	llvm::Constant* cs_struct(const cs_x86& x86);
	llvm::Function* single_step(llvm::Value* flags, const cs_insn& inst);
	
	std::string name_of(uint64_t address) const;
	
public:
	translation_context(llvm::LLVMContext& context, const x86_config& config, const std::string& module_name = "");
	~translation_context();
	
	void create_alias(uint64_t address, const std::string& name);
	result_function create_function(uint64_t base_address, const uint8_t* begin, const uint8_t* end);
	TargetInfo* create_target_info();
	
	inline llvm::Module* operator->() { return module.get(); }
	std::unique_ptr<llvm::Module> take();
};

#endif /* defined(__x86Emulator__translation_context__) */
