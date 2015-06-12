//
//  passes.h
//  x86Emulator
//
//  Created by Félix on 2015-04-21.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __x86Emulator__asaa__
#define __x86Emulator__asaa__

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Pass.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/CallGraphSCCPass.h>
SILENCE_LLVM_WARNINGS_END()

#include <unordered_map>
#include <unordered_set>

class RegisterUse : public llvm::ModulePass, public llvm::AliasAnalysis
{
	std::unordered_map<const llvm::Function*, std::unordered_map<const char*, ModRefResult>> registerUse;
	const llvm::DataLayout* layout;
	
	void runOnSCC(llvm::CallGraphSCC& scc);
	void runOnFunction(llvm::Function* fn);
	
public:
	typedef std::unordered_map<const char*, std::unordered_set<llvm::Instruction*>> DominatorsPerRegister;
	static char ID;
	
	RegisterUse();
	
	virtual const char* getPassName() const override;
	virtual void getAnalysisUsage(llvm::AnalysisUsage &au) const override;
	virtual void* getAdjustedAnalysisPointer(llvm::AnalysisID PI) override;
	
	const std::unordered_map<const char*, ModRefResult>* getModRefInfo(llvm::Function* fn) const;
	ModRefResult getModRefInfo(llvm::Function* fn, const char* registerName) const;
	virtual ModRefResult getModRefInfo(llvm::ImmutableCallSite cs, const Location& location) override;
	
	virtual bool runOnModule(llvm::Module& m) override;
	
	void dumpFn(const llvm::Function* fn) const;
	void dumpDom(const DominatorsPerRegister& dom) const;
};

llvm::ImmutablePass* createAddressSpaceAliasAnalysisPass();
RegisterUse* createRegisterUsePass();
llvm::CallGraphSCCPass* createArgumentRecoveryPass();

namespace llvm
{
	void initializeRegisterUsePass(PassRegistry& PR);
}

#endif /* defined(__x86Emulator__asaa__) */
