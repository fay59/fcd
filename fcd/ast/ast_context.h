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
#include "statements.h"

#include <unordered_map>
#include <utility>

namespace llvm
{
	class Instruction;
	class Type;
	class Value;
}

class Expression;
class ExpressionUser;

class AstContext
{
	friend class InstToExpr;
	
	DumbAllocator& pool;
	std::unordered_map<llvm::Value*, Expression*> expressionMap;
	std::unordered_map<llvm::Type*, TokenExpression*> typeMap;
	Expression* trueExpr;
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
	
	template<bool HasUses, typename T, typename... TArgs, typename = typename std::enable_if<std::is_base_of<Expression, T>::value, T>::type>
	T* allocate(unsigned useCount, TArgs&&... args)
	{
		assert(HasUses || useCount == 0);
		void* result = HasUses
			? prepareStorageAndUses(useCount, sizeof(T))
			: pool.allocateDynamic<char>(sizeof(T), alignof(T));
		return new (result) T(*this, useCount, std::forward<TArgs>(args)...);
	}
	
	template<typename T, typename... TArgs, typename = typename std::enable_if<std::is_base_of<Statement, T>::value, T>::type>
	T* allocateStatement(unsigned useCount, TArgs&&... args)
	{
		void* result = useCount == 0
			? pool.allocateDynamic<char>(sizeof(T), alignof(T))
			: prepareStorageAndUses(useCount, sizeof(T));
		return new (result) T(std::forward<TArgs>(args)...);
	}
	
public:
	AstContext(DumbAllocator& pool);
	
	DumbAllocator& getPool() { return pool; }
	
	TokenExpression* expressionFor(llvm::Type& type);
	Expression* expressionFor(llvm::Value& value);
	Expression* expressionForTrue() { return trueExpr; }
	Expression* expressionForUndef() { return undef; }
	Expression* expressionForNull() { return null; }
	
	Statement* statementFor(llvm::Instruction& inst);
	
#pragma mark - Expressions
	UnaryOperatorExpression* unary(UnaryOperatorExpression::UnaryOperatorType type, NOT_NULL(Expression) operand)
	{
		return allocate<true, UnaryOperatorExpression>(1, type, operand);
	}
	
	NAryOperatorExpression* nary(NAryOperatorExpression::NAryOperatorType type, unsigned numElements = 2)
	{
		return allocate<true, NAryOperatorExpression>(numElements, type);
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
		return allocate<true, TernaryExpression>(3, cond, ifTrue, ifFalse);
	}
	
	NumericExpression* numeric(uint64_t ui)
	{
		return allocate<false, NumericExpression>(0, ui);
	}
	
	NumericExpression* numeric(int64_t si)
	{
		return allocate<false, NumericExpression>(0, si);
	}
	
	TokenExpression* token(llvm::StringRef string)
	{
		return allocate<false, TokenExpression>(0, string);
	}
	
	CallExpression* call(NOT_NULL(Expression) callee, unsigned numParams = 0)
	{
		return allocate<true, CallExpression>(numParams + 1, callee);
	}
	
	CastExpression* cast(NOT_NULL(TokenExpression) type, NOT_NULL(Expression) value, CastExpression::CastSign sign = CastExpression::Irrelevant)
	{
		return allocate<true, CastExpression>(2, type, value, sign);
	}
	
	AggregateExpression* aggregate(unsigned numFields)
	{
		return allocate<true, AggregateExpression>(numFields);
	}
	
	SubscriptExpression* subscript(NOT_NULL(Expression) base, NOT_NULL(Expression) index)
	{
		return allocate<true, SubscriptExpression>(2, base, index);
	}
	
	AssemblyExpression* assembly(llvm::StringRef assembly)
	{
		return allocate<false, AssemblyExpression>(0, assembly);
	}
	
	AssignableExpression* assignable(NOT_NULL(TokenExpression) type, llvm::StringRef prefix)
	{
		return allocate<true, AssignableExpression>(1, type, prefix);
	}
	
#pragma mark Simple transformations
	// XXX: this might create multiple versions of fundamentaly identical expressions
	Expression* negate(NOT_NULL(Expression) expr);
	
#pragma mark - Statements
	ExpressionStatement* expr(NOT_NULL(Expression) expr)
	{
		return allocateStatement<ExpressionStatement>(1, expr);
	}
	
	SequenceStatement* sequence()
	{
		return allocateStatement<SequenceStatement>(0, pool);
	}
	
	IfElseStatement* ifElse(NOT_NULL(Expression) condition, NOT_NULL(Statement) ifBody, Statement* elseBody = nullptr)
	{
		return allocateStatement<IfElseStatement>(1, condition, ifBody, elseBody);
	}
	
	LoopStatement* loop(NOT_NULL(Expression) condition, LoopStatement::ConditionPosition pos, NOT_NULL(Statement) body)
	{
		return allocateStatement<LoopStatement>(1, condition, pos, body);
	}
	
	KeywordStatement* keyword(const char* keyword, Expression* operand = nullptr)
	{
		return allocateStatement<KeywordStatement>(1, keyword, operand);
	}
	
	KeywordStatement* breakStatement()
	{
		return keyword("break");
	}
	
	NoopStatement* noop()
	{
		return allocateStatement<NoopStatement>(0);
	}
};

#endif /* expression_context_hpp */
