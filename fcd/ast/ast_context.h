//
// expression_context.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef expression_context_hpp
#define expression_context_hpp

#include "dumb_allocator.h"
#include "expression_type.h"
#include "expressions.h"
#include "not_null.h"
#include "statements.h"

#include <memory>
#include <unordered_map>
#include <utility>

namespace llvm
{
	class Instruction;
	class Module;
	class PHINode;
	class StructType;
	class Type;
	class Value;
}

class Expression;
class ExpressionUser;

class AstContext
{
	friend class InstToExpr;
	class TypeIndex;
	
	DumbAllocator& pool;
	llvm::Module* module;
	std::unordered_map<Expression*, Expression*> phiReadsToWrites;
	std::unordered_map<llvm::Value*, Expression*> expressionMap;
	std::unique_ptr<TypeIndex> types;
	std::unordered_map<const llvm::StructType*, StructExpressionType*> structTypeMap;
	
	ExpressionReference trueExpr;
	ExpressionReference falseExpr;
	ExpressionReference undef;
	ExpressionReference null;
	
	ExpressionReference memcpyToken;
	ExpressionReference memmoveToken;
	ExpressionReference memsetToken;
	ExpressionReference trapToken;
	
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
	AstContext(DumbAllocator& pool, llvm::Module* module = nullptr);
	~AstContext();
	
	DumbAllocator& getPool() { return pool; }
	
	Expression* expressionFor(llvm::Value& value);
	Expression* expressionForTrue() { return trueExpr.get(); }
	Expression* expressionForFalse() { return falseExpr.get(); }
	Expression* expressionForUndef() { return undef.get(); }
	Expression* expressionForNull() { return null.get(); }
	
	std::vector<Expression*> allBuiltinExpressions()
	{
		return {
			trueExpr.get(), falseExpr.get(), undef.get(), null.get(),
			memcpyToken.get(), memmoveToken.get(), memsetToken.get(), trapToken.get()
		};
	}
	
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
	
	template<typename Iterator, typename = typename std::enable_if<std::is_convertible<decltype(*std::declval<Iterator>()), Expression*>::value, void>::type>
	Expression* nary(NAryOperatorExpression::NAryOperatorType type, Iterator begin, Iterator end, bool returnSingle = false)
	{
		auto count = static_cast<unsigned>(end - begin);
		assert(count > 0);
		if (count == 1 && returnSingle)
		{
			return *begin;
		}
		
		auto result = nary(type, count);
		unsigned index = 0;
		for (auto iter = begin; iter != end; ++iter)
		{
			setOperand(result, index, *iter);
			++index;
		}
		return result;
	}
	
	template<typename... TExpressionType>
	NAryOperatorExpression* nary(NAryOperatorExpression::NAryOperatorType type, TExpressionType&&... expressions)
	{
		auto result = nary(type, static_cast<unsigned>(sizeof...(TExpressionType)));
		setOperand(result, 0, std::forward<TExpressionType>(expressions)...);
		return result;
	}
	
	MemberAccessExpression* memberAccess(NOT_NULL(Expression) base, unsigned fieldIndex)
	{
		return allocate<true, MemberAccessExpression>(1, base, fieldIndex);
	}
	
	TernaryExpression* ternary(NOT_NULL(Expression) cond, NOT_NULL(Expression) ifTrue, NOT_NULL(Expression) ifFalse)
	{
		return allocate<true, TernaryExpression>(3, cond, ifTrue, ifFalse);
	}
	
	NumericExpression* numeric(const IntegerExpressionType& type, uint64_t ui)
	{
		return allocate<false, NumericExpression>(0, type, ui);
	}
	
	TokenExpression* token(const ExpressionType& type, llvm::StringRef string)
	{
		return allocate<false, TokenExpression>(0, type, string);
	}
	
	CallExpression* call(NOT_NULL(Expression) callee, unsigned numParams = 0)
	{
		return allocate<true, CallExpression>(numParams + 1, callee);
	}
	
	CastExpression* cast(const ExpressionType& type,  NOT_NULL(Expression) value)
	{
		return allocate<true, CastExpression>(1, type, value);
	}
	
	AggregateExpression* aggregate(const ExpressionType& type, unsigned numFields)
	{
		return allocate<true, AggregateExpression>(numFields, type);
	}
	
	SubscriptExpression* subscript(NOT_NULL(Expression) base, NOT_NULL(Expression) index)
	{
		return allocate<true, SubscriptExpression>(2, base, index);
	}
	
	AssemblyExpression* assembly(const FunctionExpressionType& type, llvm::StringRef assembly)
	{
		return allocate<false, AssemblyExpression>(0, type, assembly);
	}
	
	AssignableExpression* assignable(const ExpressionType& type, llvm::StringRef prefix, bool addressable = false)
	{
		return allocate<false, AssignableExpression>(0, type, prefix, addressable);
	}
	
#pragma mark Simple transformations
	// XXX: this might create multiple versions of fundamentaly identical expressions
	Expression* negate(NOT_NULL(Expression) expr);
	
#pragma mark - Statements
	ExpressionStatement* expr(NOT_NULL(Expression) expr)
	{
		return allocateStatement<ExpressionStatement>(1, expr);
	}
	
	IfElseStatement* ifElse(NOT_NULL(Expression) condition)
	{
		return allocateStatement<IfElseStatement>(1, condition);
	}
	
	IfElseStatement* ifElse(NOT_NULL(Expression) condition, StatementReference&& ifBody)
	{
		return allocateStatement<IfElseStatement>(1, condition, std::move(ifBody).take());
	}
	
	IfElseStatement* ifElse(NOT_NULL(Expression) condition, StatementReference&& ifBody, StatementReference&& elseBody)
	{
		return allocateStatement<IfElseStatement>(1, condition, std::move(ifBody).take(), std::move(elseBody).take());
	}
	
	LoopStatement* loop(NOT_NULL(Expression) condition, LoopStatement::ConditionPosition pos)
	{
		return allocateStatement<LoopStatement>(1, condition, pos);
	}
	
	LoopStatement* loop(NOT_NULL(Expression) condition, LoopStatement::ConditionPosition pos, StatementList&& body)
	{
		return allocateStatement<LoopStatement>(1, condition, pos, std::move(body));
	}
	
	KeywordStatement* keyword(const char* keyword, Expression* operand = nullptr)
	{
		return allocateStatement<KeywordStatement>(1, keyword, operand);
	}
	
	KeywordStatement* breakStatement()
	{
		return keyword("break");
	}
	
	Statement* breakStatement(NOT_NULL(Expression) condition)
	{
		if (condition == expressionForTrue())
		{
			return breakStatement();
		}
		else
		{
			return ifElse(condition, { breakStatement() });
		}
	}
	
#pragma mark - Φ Nodes
	ExpressionStatement* phiAssignment(llvm::PHINode& phi, llvm::Value& value);
	
#pragma mark - Types
	const ExpressionType& getType(llvm::Type& type);
	const VoidExpressionType& getVoid();
	const IntegerExpressionType& getIntegerType(bool isSigned, unsigned short numBits);
	const PointerExpressionType& getPointerTo(const ExpressionType& pointee);
	const ArrayExpressionType& getArrayOf(const ExpressionType& elementType, size_t numElements);
	StructExpressionType& createStructure(std::string name);
	FunctionExpressionType& createFunction(const ExpressionType& returnType);
};

#endif /* expression_context_hpp */
