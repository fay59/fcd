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

#ifndef fcd__translation_context_h
#define fcd__translation_context_h

#include "capstone_wrapper.h"
#include "code_generator.h"
#include "executable.h"
#include "targetinfo.h"
#include "translation_maps.h"
#include "x86_regs.h"

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LLVMContext.h>

#include <memory>
#include <unordered_map>
#include <unordered_set>

class CodeGenerator;

class TranslationContext
{
	llvm::LLVMContext& context;
	std::unique_ptr<capstone> cs;
	std::unique_ptr<CodeGenerator> irgen;
	std::unique_ptr<llvm::Module> module;
	std::unique_ptr<AddressToFunction> functionMap;
	
	llvm::FunctionType* resultFnTy;
	llvm::GlobalVariable* configVariable;
	
	llvm::CastInst& getPointer(llvm::Value* intptr, size_t size);
	std::string nameOf(uint64_t address) const;
	
public:
	TranslationContext(llvm::LLVMContext& context, const x86_config& config, const std::string& module_name = "");
	~TranslationContext();
	
	void setFunctionName(uint64_t address, const std::string& name);
	llvm::Function* createFunction(Executable& executable, uint64_t base_address);
	std::unordered_set<uint64_t> getDiscoveredEntryPoints() const;
	
	inline llvm::Module* operator->() { return module.get(); }
	std::unique_ptr<llvm::Module> take();
};

#endif /* defined(fcd__translation_context_h) */
