//
// expression_context.h
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

#ifndef expression_context_hpp
#define expression_context_hpp

#include "dumb_allocator.h"
#include "expressions.h"
#include "llvm_warnings.h"
#include "not_null.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/SmallVector.h>
SILENCE_LLVM_WARNINGS_END()

#include <unordered_map>

namespace llvm
{
	class Value;
}

class ExpressionContext
{
	friend class InstToExpr;
	
	DumbAllocator& pool;
	std::unordered_map<llvm::Value*, Expression*> expressionMap;
	Expression* undef;
	Expression* null;
	
	Expression* uncachedExpressionFor(llvm::Value& value);
	
public:
	ExpressionContext(DumbAllocator& pool);
	
	Expression* expressionFor(llvm::Value& value);
	Expression* expressionForUndef() { return undef; }
	Expression* expressionForNull() { return null; }
};

#endif /* expression_context_hpp */
