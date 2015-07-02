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

#include "dumb_allocator.h"
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

namespace llvm
{
	class DominanceFrontier;
	class DominatorTree;
}

class AstNode
{
public:
	enum AstNodeType
	{
		Value, Sequence, IfElse, Goto
	};
	
	void dump() const;
	virtual void print(llvm::raw_ostream& os, unsigned indent = 0) const = 0;
	virtual AstNodeType getType() const = 0;
};

struct ValueNode : public AstNode
{
	llvm::Value* value;

	static bool classof(const AstNode* node)
	{
		return node->getType() == Value;
	}
	
	inline explicit ValueNode(llvm::Value& value) : value(&value)
	{
	}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline AstNodeType getType() const override { return Value; }
};

struct SequenceNode : public AstNode
{
	AstNode** nodes;
	size_t count;
	
	static bool classof(const AstNode* node)
	{
		return node->getType() == Sequence;
	}
	
	inline SequenceNode(AstNode** nodes, size_t count) : nodes(nodes), count(count)
	{
	}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline AstNodeType getType() const override { return Sequence; }
};

struct IfElseNode : public AstNode
{
	AstNode* condition;
	AstNode* ifBody;
	AstNode* elseBody;
	
	static bool classof(const AstNode* node)
	{
		return node->getType() == IfElse;
	}
	
	inline IfElseNode(AstNode* condition, AstNode* ifBody, AstNode* elseBody = nullptr)
	: condition(condition), ifBody(ifBody), elseBody(elseBody)
	{
	}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline AstNodeType getType() const override { return IfElse; }
};

struct GotoNode : public AstNode
{
	llvm::BasicBlock* target;
	
	static bool classof(const AstNode* node)
	{
		return node->getType() == Goto;
	}
	
	inline explicit GotoNode(llvm::BasicBlock& target) : target(&target)
	{
	}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
	virtual inline AstNodeType getType() const override { return Goto; }
};

// XXX Make this a legit LLVM backend?
// Doesn't sound like a bad idea, but I don't really know where to start.
class AstBackEnd : public llvm::ModulePass
{
	// cleared on run
	DumbAllocator<> astAllocator;
	std::unordered_map<const llvm::Function*, AstNode*> astPerFunction;
	
	// cleared on runOnFunction
	std::unordered_map<llvm::BasicBlock*, llvm::BasicBlock*> postDomTraversalShortcuts;
	std::unordered_map<const llvm::BasicBlock*, AstNode*> astPerBlock;
	llvm::DominanceFrontier* domFrontier;
	llvm::DominatorTree* domTree;
	
	AstNode* toAstNode(llvm::BasicBlock& block);
	
	bool isRegion(llvm::BasicBlock* entry, llvm::BasicBlock* exit);
	bool runOnFunction(llvm::Function& fn);
	bool runOnLoop(llvm::Loop& loop);
	bool runOnRegion(llvm::BasicBlock& entry, llvm::BasicBlock& exit);
	
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
	
	const AstNode* astForFunction(const llvm::Function& fn) const;
};

#endif /* program_output_cpp */
