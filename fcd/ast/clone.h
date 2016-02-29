//
// clone.h
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
