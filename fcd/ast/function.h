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
	llvm::Function& function;
	llvm::Type* returnType;
	std::list<DeclarationStatement*> declarations;
	std::unordered_map<llvm::Value*, Expression*> valueMap;
	std::unordered_map<llvm::Value*, Expression*> rawValueMap;
	std::unordered_map<llvm::Value*, Expression*> lvalueMap;
	
	Expression* indexIntoElement(Expression* base, llvm::Type* type, llvm::Value* index);
	
	std::string createName(const std::string& prefix) const;
	Expression* createDeclaration(llvm::Type& type);
	Expression* createDeclaration(llvm::Type& type, const std::string& name);
	void assign(Expression* left, Expression* right);
	Expression* lvalueFor(llvm::Value& value);
	Statement* statementFor(llvm::Instruction& inst);
	
public:
	typedef decltype(declarations)::iterator declaration_iterator;
	
	DumbAllocator pool;
	Statement* body;
	
	static void printIntegerConstant(llvm::raw_ostream&& os, uint64_t constant);
	static void printIntegerConstant(llvm::raw_ostream& os, uint64_t constant);
	static void printPrototype(llvm::raw_ostream& os, llvm::Function& function, llvm::Type* returnType = nullptr);
	
	inline FunctionNode(llvm::Function& fn)
	: function(fn), body(nullptr), returnType(nullptr)
	{
	}
	
	inline declaration_iterator decls_begin() { return declarations.begin(); }
	inline declaration_iterator decls_end() { return declarations.end(); }
	inline declaration_iterator erase(declaration_iterator iter) { return declarations.erase(iter); }
	
	SequenceStatement* basicBlockToStatement(llvm::BasicBlock& bb);
	Expression* valueFor(llvm::Value& value);
	inline llvm::Function& getFunction() { return function; }
	
	inline void setReturnType(llvm::Type& type) { returnType = &type; }
	inline llvm::Type& getReturnType() const
	{
		return returnType == nullptr ? *function.getReturnType() : *returnType;
	}
	
	bool hasBody() const { return declarations.size() > 0 || body != nullptr; }
	
	void print(llvm::raw_ostream& os) const;
	void dump() const;
};

#endif /* fcd__ast_function_h */
