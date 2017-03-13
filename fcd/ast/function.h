//
// function.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__ast_function_h
#define fcd__ast_function_h

#include "statements.h"
#include "dumb_allocator.h"
#include "ast_context.h"

#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>

#include <list>
#include <unordered_map>

// The FunctionNode's lifetime is tied to the lifetime of its memory pool (because the lifetime of almost everything it
// contains is), but it is not itself intended to be allocated through the DumbAllocator interface. FunctionNode needs
// more complex data structures that I have no intention of replicating à la PooledDeque, and thus has a non-trivial
// destructor.
class FunctionNode
{
	llvm::Function& function;
	DumbAllocator pool;
	AstContext context;
	StatementReference body;
	
public:
	FunctionNode(llvm::Function& fn)
	: function(fn), context(pool, fn.getParent())
	{
	}
	
	DumbAllocator& getPool() { return pool; }
	AstContext& getContext() { return context; }
	llvm::Function& getFunction() { return function; }
	
	llvm::Type& getReturnType() const
	{
		return *function.getReturnType();
	}
	
	StatementList& getBody() { return *body; }
	bool hasBody() const { return !body->empty(); }
	
	void print(llvm::raw_ostream& os);
	void dump() const;
};

#endif /* fcd__ast_function_h */
