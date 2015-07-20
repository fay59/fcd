//
//  ast_simplify.hpp
//  x86Emulator
//
//  Created by Félix on 2015-07-18.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#ifndef ast_simplify_cpp
#define ast_simplify_cpp

#include "ast_nodes.h"
#include "dumb_allocator.h"

Expression* wrapWithNegate(DumbAllocator& pool, Expression* toNegate);
Statement* recursivelySimplifyStatement(DumbAllocator& pool, Statement* statement);
void recursivelySimplifyConditions(DumbAllocator& pool, Statement* statement);

#endif /* ast_simplify_cpp */
