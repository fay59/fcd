//
// pass_argrec.h
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

#ifndef pass_argrec_h
#define pass_argrec_h

#include "llvm_warnings.h"
#include "params_registry.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Analysis/Passes.h>
#include <llvm/IR/Module.h>
SILENCE_LLVM_WARNINGS_END()

#include <unordered_map>

class ArgumentRecovery : public llvm::ModulePass
{
	std::unordered_map<const llvm::Function*, llvm::Value*> registerPtr;
	
	bool isRecoverable(llvm::Function& fn);
	llvm::Value* getRegisterPtr(llvm::Function& fn);
	
	llvm::Function& createParameterizedFunction(llvm::Function& base, const CallInformation& ci);
	void fixCallSites(llvm::Function& base, llvm::Function& newTarget, const CallInformation& ci);
	llvm::Value* createReturnValue(llvm::Function& function, const CallInformation& ci, llvm::Instruction* insertionPoint);
	void updateFunctionBody(llvm::Function& oldFunction, llvm::Function& newTarget, const CallInformation& ci);
	bool recoverArguments(llvm::Function& fn);
	
public:
	static char ID;
	
	ArgumentRecovery() : ModulePass(ID)
	{
	}
	
	static llvm::FunctionType* createFunctionType(TargetInfo& targetInfo, llvm::LLVMContext& ctx, const CallInformation& ci, llvm::StringRef returnTypeName = "");
	static llvm::FunctionType* createFunctionType(TargetInfo& targetInfo, llvm::LLVMContext& ctx, const CallInformation& ci, llvm::StringRef returnTypeName, llvm::SmallVectorImpl<std::string>& parameterNames);
	static llvm::CallInst* createCallSite(TargetInfo& targetInfo, const CallInformation& ci, llvm::Value& callee, llvm::Value& callerRegisters, llvm::Instruction& insertionPoint);
	
	virtual void getAnalysisUsage(llvm::AnalysisUsage& au) const override;
	virtual bool runOnModule(llvm::Module& module) override;
};

llvm::ModulePass* createArgumentRecoveryPass();

namespace llvm
{
	void initializeArgumentRecoveryPass(PassRegistry& pr);
}

#endif /* pass_argrec_h */
