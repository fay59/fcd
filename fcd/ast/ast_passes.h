//
// ast_passes.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__ast_ast_passes_h
#define fcd__ast_ast_passes_h

#include "pass.h"
#include "pass_print.h"

// Combines control flow statements.
class AstBranchCombine final : public AstFunctionPass
{
protected:
	virtual void doRun(FunctionNode& fn) override;
	
public:
	virtual const char* getName() const override;
};

// Removes assignments to __undefined.
class AstRemoveUndef final : public AstFunctionPass
{
protected:
	virtual void doRun(FunctionNode& fn) override;
	
public:
	virtual const char* getName() const override;
};

// Simplifies expressions.
class AstSimplifyExpressions final : public AstFunctionPass
{
	virtual void doRun(FunctionNode& fn) override;
	
public:
	virtual const char* getName() const override;
};

// Merges variables.
// (Do note that the current implementation is *not* idempotent! Only the first run is assumed to be correct.)
class AstMergeCongruentVariables : public AstFunctionPass {
	virtual void doRun(FunctionNode& fn) override;
	
public:
	virtual const char* getName() const override;
};

#endif /* fcd__ast_ast_passes_h */
