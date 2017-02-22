//
// clone.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__ast_clone_h
#define fcd__ast_clone_h

#include "ast_context.h"

class CloneVisitor
{
public:
	static NOT_NULL(Expression) clone(AstContext& context, const Expression& toClone);
	static NOT_NULL(Statement) clone(AstContext& context, const Statement& toClone);
	static NOT_NULL(ExpressionUser) clone(AstContext& context, const ExpressionUser& toClone);
};

#endif /* fcd__ast_clone_h */
