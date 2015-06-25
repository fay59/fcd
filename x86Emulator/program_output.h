//
//  program_output.hpp
//  x86Emulator
//
//  Created by Félix on 2015-06-16.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

//
// The algorithm used here is based off K. Yakdan, S. Eschweiler, E. Gerhards-Padilla
// and M. Smith's research paper "No More Gotos", accessible from the Internet Society's website:
// http://www.internetsociety.org/doc/no-more-gotos-decompilation-using-pattern-independent-control-flow-structuring-and-semantics
//

#ifndef program_output_cpp
#define program_output_cpp

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/RegionInfo.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <memory>
#include <unordered_map>

class AstNode
{
public:
	virtual void print(llvm::raw_ostream& os, unsigned indent = 0) const = 0;
	virtual ~AstNode();
};

class SequenceNode : public AstNode
{
public:
	virtual void print(llvm::raw_ostream& os, unsigned indent = 0) const override;
};

class ConditionNode : public AstNode
{
public:
	virtual void print(llvm::raw_ostream& os, unsigned indent = 0) const override;
};

class SwitchNode : public AstNode
{
public:
	virtual void print(llvm::raw_ostream& os, unsigned indent = 0) const override;
};

class GotoNode : public AstNode
{
public:
	virtual void print(llvm::raw_ostream& os, unsigned indent = 0) const override;
};

// XXX Make this a legit LLVM backend?
// Doesn't sound like a bad idea, but I don't really know where to start.
class AstBackEnd : public llvm::ModulePass
{
	static char ID;
	std::unordered_map<const llvm::Function*, std::unique_ptr<AstNode>> astPerFunction;
	
	bool runOnFunction(llvm::Function& fn);
	bool runOnLoop(llvm::Loop& loop);
	bool runOnRegion(llvm::Region& region);
	
public:
	inline AstBackEnd() : ModulePass(ID)
	{
	}
	
	inline virtual const char* getPassName() const override
	{
		return "AST Back-End";
	}
	
	virtual void getAnalysisUsage(llvm::AnalysisUsage &au) const override;
	virtual bool runOnModule(llvm::Module& m) override;
	
	const AstNode* astForFunction(const llvm::Function& fn) const;
};

#endif /* program_output_cpp */
