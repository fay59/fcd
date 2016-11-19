//
// pass_backend.h
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

//
// The algorithm used here is based off K. Yakdan, S. Eschweiler, E. Gerhards-Padilla
// and M. Smith's research paper "No More Gotos", accessible from the Internet Society's website:
// http://www.internetsociety.org/doc/no-more-gotos-decompilation-using-pattern-independent-control-flow-structuring-and-semantics
//

#ifndef fcd__ast_pass_backend_h
#define fcd__ast_pass_backend_h

#include "dumb_allocator.h"
#include "function.h"
#include "pass.h"
#include "pre_ast_cfg.h"
#include "statements.h"

#include <llvm/Analysis/DominanceFrontier.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/Analysis/LoopInfoImpl.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include <deque>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

// XXX Make this a legit LLVM backend?
// Doesn't sound like a bad idea, but I don't really know where to start.
class AstBackEnd final : public llvm::ModulePass
{
	std::unique_ptr<PreAstContext> blockGraph;
	std::deque<std::unique_ptr<FunctionNode>> outputNodes;
	std::deque<std::unique_ptr<AstModulePass>> passes;
	FunctionNode* output;
	
	inline DumbAllocator& pool() { return output->getPool(); }
	
	void runOnFunction(llvm::Function& fn);
	void runOnLoop(llvm::Function& fn, llvm::BasicBlock& entry, llvm::BasicBlock* exit);
	void runOnRegion(llvm::Function& fn, llvm::BasicBlock& entry, llvm::BasicBlock* exit);
	
public:
	static char ID;
	
	inline AstBackEnd()
	: ModulePass(ID)
	{
	}
	
	inline virtual const char* getPassName() const override
	{
		return "AST Back-End";
	}
	
	virtual void getAnalysisUsage(llvm::AnalysisUsage &au) const override;
	virtual bool runOnModule(llvm::Module& m) override;
	
	void addPass(AstModulePass* pass);
};

AstBackEnd* createAstBackEnd();

#endif /* fcd__ast_pass_backend_h */
