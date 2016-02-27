//
// function.h
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

#ifndef fcd__ast_function_h
#define fcd__ast_function_h

#include "statements.h"
#include "dumb_allocator.h"
#include "expression_context.h"
#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <list>
#include <unordered_map>

// The FunctionNode's lifetime is tied to the lifetime of its memory pool (because the lifetime of almost everything it
// contains is), but it is not itself intended to be allocated through the DumbAllocator interface. FunctionNode needs
// more complex data structures that I have no intention of replicating à la PooledDeque, and thus has a non-trivial
// destructor.
class FunctionNode
{
	DumbAllocator pool;
	llvm::Function& function;
	ExpressionContext context;
	Statement* body;
	
	void assign(Expression* left, Expression* right);
	Statement* statementFor(llvm::Instruction& inst);
	
public:
	static void printIntegerConstant(llvm::raw_ostream&& os, uint64_t constant);
	static void printIntegerConstant(llvm::raw_ostream& os, uint64_t constant);
	static void printPrototype(llvm::raw_ostream& os, llvm::Function& function, llvm::Type* returnType = nullptr);
	
	FunctionNode(llvm::Function& fn)
	: function(fn), context(pool), body(nullptr)
	{
	}
	
	SequenceStatement* basicBlockToStatement(llvm::BasicBlock& bb);
	Expression* valueFor(llvm::Value& value) { return context.expressionFor(value); }
	
	DumbAllocator& getPool() { return pool; }
	llvm::Function& getFunction() { return function; }
	
	llvm::Type& getReturnType() const
	{
		return *function.getReturnType();
	}
	
	void setBody(Statement* body) { this->body = body; }
	Statement* getBody() { return body; }
	bool hasBody() const { return body != nullptr; }
	
	void print(llvm::raw_ostream& os) const;
	void dump() const;
};

#endif /* fcd__ast_function_h */
