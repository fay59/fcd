//
// pass.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__ast_pass_h
#define fcd__ast_pass_h

#include "function.h"

#include <deque>

// Lifetime management for an AST pass is the same as for a LLVM pass: the pass manager owns it.
class AstModulePass
{
protected:
	virtual void doRun(std::deque<std::unique_ptr<FunctionNode>>& functions) = 0;
	
public:
	virtual const char* getName() const = 0;
	void run(std::deque<std::unique_ptr<FunctionNode>>& functions);
	virtual ~AstModulePass() = default;
};

class AstFunctionPass : public AstModulePass
{
	FunctionNode* fn;
	bool runOnDeclarations;
	
protected:
	AstContext& context() { return fn->getContext(); }
	
	virtual void doRun(std::deque<std::unique_ptr<FunctionNode>>& function) override final;
	virtual void doRun(FunctionNode& function) = 0;
	
public:
	AstFunctionPass(bool runOnDeclarations = false)
	: runOnDeclarations(runOnDeclarations)
	{
	}
	
	virtual ~AstFunctionPass() = default;
};

#endif /* fcd__ast_pass_h */
