//
// pass.h
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
	
	// Transformation helpers.
	Expression* negate(Expression* that);
	Statement* append(Statement* a, Statement* b);
	
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
