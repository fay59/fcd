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
#include "not_null.h"

#include <unordered_map>
#include <utility>

namespace llvm
{
	class Value;
	class Type;
}

class Expression;
class ExpressionUser;

class AstContext
{
	friend class InstToExpr;
	
	DumbAllocator& pool;
	std::unordered_map<llvm::Value*, Expression*> expressionMap;
	std::unordered_map<llvm::Type*, TokenExpression*> typeMap;
	Expression* undef;
	Expression* null;
	
	Expression* uncachedExpressionFor(llvm::Value& value);
	
	void* prepareStorageAndUses(unsigned useCount, size_t storageSize);
	
	template<typename T, typename... TElements>
	void setOperand(T* object, unsigned index, NOT_NULL(Expression) expression, TElements&&... elems)
	{
		setOperand(object, index, expression);
		setOperand(object, index + 1, std::forward<TElements>(elems)...);
	}
	
	template<typename T>
	void setOperand(T* object, unsigned index, NOT_NULL(Expression) expr)
	{
		object->setOperand(index, expr);
	}
	
public:
	AstContext(DumbAllocator& pool);
	
	DumbAllocator& getPool() { return pool; }
	
	TokenExpression* expressionFor(llvm::Type& type);
	Expression* expressionFor(llvm::Value& value);
	Expression* expressionForUndef() { return undef; }
	Expression* expressionForNull() { return null; }
	
	template<typename T, typename... TArgs, typename = typename std::enable_if<std::is_base_of<ExpressionUser, T>::value, T>::type>
	T* allocate(unsigned useCount, TArgs&&... args)
	{
		void* result = prepareStorageAndUses(useCount, sizeof(T));
		return new (result) T(*this, useCount, std::forward<TArgs>(args)...);
	}
	
	UnaryOperatorExpression* unary(UnaryOperatorExpression::UnaryOperatorType type, NOT_NULL(Expression) operand)
	{
		return allocate<UnaryOperatorExpression>(1, type, operand);
	}
	
	NAryOperatorExpression* nary(NAryOperatorExpression::NAryOperatorType type, unsigned numElements = 2)
	{
		return allocate<NAryOperatorExpression>(numElements, type);
	}
	
	template<typename... TExpressionType>
	NAryOperatorExpression* nary(NAryOperatorExpression::NAryOperatorType type, TExpressionType&&... expressions)
	{
		auto result = nary(type, static_cast<unsigned>(sizeof...(TExpressionType)));
		setOperand(result, 0, std::forward<TExpressionType>(expressions)...);
		return result;
	}
	
	TernaryExpression* ternary(NOT_NULL(Expression) cond, NOT_NULL(Expression) ifTrue, NOT_NULL(Expression) ifFalse)
	{
		return allocate<TernaryExpression>(3, cond, ifTrue, ifFalse);
	}
	
	NumericExpression* numeric(uint64_t ui)
	{
		return allocate<NumericExpression>(0, ui);
	}
	
	NumericExpression* numeric(int64_t si)
	{
		return allocate<NumericExpression>(0, si);
	}
	
	TokenExpression* token(llvm::StringRef string)
	{
		return allocate<TokenExpression>(0, string);
	}
	
	CallExpression* call(NOT_NULL(Expression) callee, unsigned numParams = 0)
	{
		return allocate<CallExpression>(numParams, callee);
	}
	
	CastExpression* cast(NOT_NULL(TokenExpression) type, NOT_NULL(Expression) value, CastExpression::CastSign sign = CastExpression::Irrelevant)
	{
		return allocate<CastExpression>(2, type, value, sign);
	}
	
	AggregateExpression* aggregate(unsigned numFields)
	{
		return allocate<AggregateExpression>(numFields);
	}
	
	SubscriptExpression* subscript(NOT_NULL(Expression) base, NOT_NULL(Expression) index)
	{
		return allocate<SubscriptExpression>(2, base, index);
	}
	
	AssemblyExpression* assembly(llvm::StringRef assembly)
	{
		return allocate<AssemblyExpression>(0, assembly);
	}
	
	AssignableExpression* assignable(NOT_NULL(TokenExpression) type, llvm::StringRef prefix)
	{
		return allocate<AssignableExpression>(1, type, prefix);
	}
};

#endif /* expression_context_hpp */
