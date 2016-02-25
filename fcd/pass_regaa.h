//
// pass_regaa.h
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

#ifndef pass_regaa_h
#define pass_regaa_h

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Pass.h>
SILENCE_LLVM_WARNINGS_END()

#include <memory>

class ProgramMemoryAAResult : public llvm::AAResultBase<ProgramMemoryAAResult>
{
	friend llvm::AAResultBase<ProgramMemoryAAResult>;
	
public:
	ProgramMemoryAAResult(const llvm::TargetLibraryInfo& tli)
	: AAResultBase(tli)
	{
	}
	
	ProgramMemoryAAResult(const ProgramMemoryAAResult&) = default;
	ProgramMemoryAAResult(ProgramMemoryAAResult&&) = default;
	
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
