//
// pass_regaa.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef pass_regaa_h
#define pass_regaa_h

#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Pass.h>

#include <memory>

class ProgramMemoryAAResult : public llvm::AAResultBase<ProgramMemoryAAResult>
{
	friend llvm::AAResultBase<ProgramMemoryAAResult>;
	
public:
	bool invalidate(llvm::Function& fn, const llvm::PreservedAnalyses& pa)
	{
		// Stateless.
		return false;
	}
	
	llvm::AliasResult alias(const llvm::MemoryLocation& a, const llvm::MemoryLocation& b);
};

class ProgramMemoryAAWrapperPass : public llvm::ImmutablePass
{
	std::unique_ptr<ProgramMemoryAAResult> result;
	
public:
	static char ID;
	
	ProgramMemoryAAWrapperPass();
	~ProgramMemoryAAWrapperPass();
	
	ProgramMemoryAAResult& getResult();
	const ProgramMemoryAAResult& getResult() const;
	
	virtual bool doInitialization(llvm::Module& m) override;
	virtual bool doFinalization(llvm::Module& m) override;
	virtual void getAnalysisUsage(llvm::AnalysisUsage& au) const override;
};

llvm::ImmutablePass* createProgramMemoryAliasAnalysis();

#endif /* pass_regaa_h */
