//
//  output_model.h
//  interpiler
//
//  Created by Félix on 2015-04-11.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef interpiler_output_model_h
#define interpiler_output_model_h

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/GlobalVariable.h>

class output_model
{
	llvm::LLVMContext& context;
	llvm::Module& module;
	std::vector<llvm::Type*> types;
	std::vector<llvm::GlobalVariable*> globals;
	
	llvm::Function* currentFunction;
	llvm::BasicBlock* lastBlock;
};

#endif
