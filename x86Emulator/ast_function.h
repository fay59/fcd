//
//  ast_function.hpp
//  x86Emulator
//
//  Created by Félix on 2015-07-20.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#ifndef ast_function_cpp
#define ast_function_cpp

#include "ast_nodes.h"
#include "dumb_allocator.h"
#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <unordered_map>
#include <unordered_set>
#include <vector>


// The FunctionNode's lifetime is tied to the lifetime of its memory pool (because the lifetime of almost everything it
// contains is), but it is not itself intended to be allocated through the DumbAllocator interface. FunctionNode needs
// more complex data structures that I have no intention of replicating à la PooledDeque, and thus has a non-trivial
// destructor.
class FunctionNode
{
	llvm::Function& function;
	std::vector<DeclarationNode*> declarations;
	std::unordered_set<llvm::Value*> valuesWithDeclaration;
	std::unordered_map<llvm::Value*, Expression*> valueMap;
	
	Expression* createDeclaration(llvm::Value& value);
	Expression* createDeclaration(llvm::Value& value, const std::string& name);
	Expression* getLvalueFor(llvm::Value& value);
	void identifyLocals(llvm::Argument& stackPointer);
	
public:
	DumbAllocator pool;
	Statement* body;
	
	static void printPrototype(llvm::raw_ostream& os, llvm::Function& function);
	
	// HACKHACK: I'm not so comfortable receiving a parameter to help disambiguate the stack poiner
	// and figure out locals.
	inline FunctionNode(llvm::Function& fn, llvm::Argument& stackPointer)
	: function(fn)
	{
		body = nullptr; // manually assign this one
		identifyLocals(stackPointer);
	}
	
	SequenceNode* basicBlockToStatement(llvm::BasicBlock& bb);
	Expression* getValueFor(llvm::Value& value);
	
	void print(llvm::raw_ostream& os) const;
	void dump() const;
};

#endif /* ast_function_cpp */
