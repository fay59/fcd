//
// ast_backend.h
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

#ifndef program_output_cpp
#define program_output_cpp

#include "ast_function.h"
#include "ast_grapher.h"
#include "ast_nodes.h"
#include "ast_pass.h"
#include "dumb_allocator.h"
#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Analysis/DominanceFrontier.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
SILENCE_LLVM_WARNINGS_END()

#include <deque>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

// XXX Make this a legit LLVM backend?
// Doesn't sound like a bad idea, but I don't really know where to start.
class AstBackEnd : public llvm::ModulePass
{
	enum RegionType
	{
		NotARegion, // Entry and exit don't form a region
		Acyclic, // Entry and exit form a region, and no node in the region goes back to the region header
		Cyclic, // Entry and exit form a region, and at least one node in the region goes back to the region header
	};
	
	std::unique_ptr<FunctionNode> output;
	std::unique_ptr<AstGrapher> grapher;
	std::unordered_map<const llvm::Function*, std::string> codeForFunctions;
	std::deque<std::unique_ptr<AstPass>> passes;
	
	llvm::DominatorTree* domTree;
	llvm::PostDominatorTree* postDomTree;
	llvm::DominanceFrontier* frontier;
	
	inline DumbAllocator& pool() { return output->pool; }
	bool runOnFunction(llvm::Function& fn);
	bool runOnLoop(llvm::Function& fn, llvm::BasicBlock& entry, llvm::BasicBlock* exit);
	bool runOnRegion(llvm::Function& fn, llvm::BasicBlock& entry, llvm::BasicBlock* exit);
	RegionType isRegion(llvm::BasicBlock& entry, llvm::BasicBlock* exit);
	
public:
	static char ID;
	
	inline AstBackEnd() : ModulePass(ID)
	{
	}
	
	inline virtual const char* getPassName() const override
	{
		return "AST Back-End";
	}
	
	virtual void getAnalysisUsage(llvm::AnalysisUsage &au) const override;
	virtual bool runOnModule(llvm::Module& m) override;
	
	void addPass(AstPass* pass);
	
	std::unordered_map<const llvm::Function*, std::string> getResult() &&;
};

#endif /* program_output_cpp */
