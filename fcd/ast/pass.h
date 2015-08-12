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

#ifndef ast_pass_cpp
#define ast_pass_cpp

#include "function.h"

// Lifetime management for an AST pass is the same as for a LLVM pass: the pass manager owns it.
class AstPass
{
	DumbAllocator* pool_;
	
protected:
	// Transformation helpers.
	Expression* negate(Expression* that);
	Expression* append(NAryOperatorExpression::NAryOperatorType opcode, Expression* a, Expression* b);
	Statement* append(Statement* a, Statement* b);
	
	virtual void doRun(FunctionNode& fn) = 0;
	inline DumbAllocator& pool() { return *pool_; }
	
public:
	virtual const char* getName() const = 0;
	void run(FunctionNode& fn);
	virtual ~AstPass() = default;
};

#endif /* ast_pass_cpp */
