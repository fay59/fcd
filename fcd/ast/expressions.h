//
// expressions.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__ast_expressions_h
#define fcd__ast_expressions_h

#include "dumb_allocator.h"
#include "expression_type.h"
#include "expression_use.h"
#include "expression_user.h"
#include "not_null.h"

#include <llvm/ADT/iterator_range.h>

#include <string>

class AstContext;
class Statement;

class Expression : public ExpressionUser
{
	template<bool B, typename T>
	using OptionallyConst = typename std::conditional<B, typename std::add_const<T>::type, typename std::remove_const<T>::type>::type;
	
	friend class ExpressionUse;
	
private:
	class ExpressionUse* firstUse;
	
protected:
	static bool defaultEqualityCheck(const Expression& a, const Expression& b);
	
public:
	// This iterator could almost be bidirectional, but uses have no sentinel value, so it would be impossible to go
	// back from the last element of the sequence.
	template<bool IsConst>
	class UseIterator : public std::iterator<std::forward_iterator_tag, OptionallyConst<IsConst, ExpressionUse>>
	{
		OptionallyConst<IsConst, ExpressionUse>* current;
		
	public:
		UseIterator(OptionallyConst<IsConst, ExpressionUse>* use)
		: current(use)
		{
		}
		
		UseIterator(const UseIterator&) = default;
		UseIterator(UseIterator&&) = default;
		
		OptionallyConst<IsConst, ExpressionUse>& operator*() { return *operator->(); }
		OptionallyConst<IsConst, ExpressionUse>* operator->() { return current; }
		
		template<bool B>
		bool operator==(const UseIterator<B>& that) const { return current == that.current; }
		
		template<bool B>
		bool operator!=(const UseIterator<B>& that) const { return !(*this == that); }
		
		UseIterator& operator++() { current = current->getNext(); return *this; }
		UseIterator operator++(int)
		{
			UseIterator copy = *this;
			operator++();
			return copy;
		}
	};
	
	typedef UseIterator<false> use_iterator;
	typedef UseIterator<true> const_use_iterator;
	
	static bool classof(const ExpressionUser* user)
	{
		return user->getUserType() >= ExpressionMin && user->getUserType() < ExpressionMax;
	}
	
	Expression(UserType type, AstContext& ctx, unsigned allocatedUses, unsigned usedUses)
	: ExpressionUser(type, allocatedUses, usedUses), firstUse(nullptr)
	{
		assert(type >= ExpressionMin && type < ExpressionMax);
		// The context parameter only forces subclasses to accept one, for uniformity purposes.
		(void)ctx;
	}
	
	Expression(UserType type, AstContext& ctx, unsigned uses)
	: Expression(type, ctx, uses, uses)
	{
	}
	
	use_iterator uses_begin() { return use_iterator(firstUse); }
	const_use_iterator uses_begin() const { return const_use_iterator(firstUse); }
	const_use_iterator uses_cbegin() const { return uses_begin(); }
	
	use_iterator uses_end() { return use_iterator(nullptr); }
	const_use_iterator uses_end() const { return const_use_iterator(nullptr); }
	const_use_iterator uses_cend() const { return uses_end(); }
	
	llvm::iterator_range<use_iterator> uses() { return llvm::make_range(uses_begin(), uses_end()); }
	llvm::iterator_range<const_use_iterator> uses() const { return llvm::make_range(uses_begin(), uses_end()); }
	
	// Be mindful that this counts uses from unreferenced users too (which is rarely what you want).
	// For best results, the AST should be cloned.
	unsigned uses_size() const;
	bool uses_empty() const { return firstUse == nullptr; }
	bool uses_many() const { return firstUse != nullptr && firstUse->getNext() != nullptr; }
	
	void replaceAllUsesWith(Expression* expression);
	
	Statement* ancestorOfAllUses();
	const Statement* ancestorOfAllUses() const { return const_cast<Expression*>(this)->ancestorOfAllUses(); }
	
	virtual const ExpressionType& getExpressionType(AstContext& context) const = 0;
	virtual bool operator==(const Expression& that) const = 0;
	
	bool operator!=(const Expression& that) const
	{
		return !(*this == that);
	}
};

class UnaryOperatorExpression final : public Expression
{
public:
	enum UnaryOperatorType : unsigned
	{
		Min = 0,
		
		// The SSA form ensures that we will never need a distinction between prefix and postfix increment/decrement.
		// That's why there's only one of each. We will, however, prefer the prefix version because postfix ++ and --
		// are the only postfix unary operators.
		Increment = Min, Decrement,
		AddressOf, Dereference,
		ArithmeticNegate, LogicalNegate, BinaryNegate,
		Max
	};
	
private:
	UnaryOperatorType type;
	
public:
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == UnaryOperator;
	}
	
	UnaryOperatorExpression(AstContext& ctx, unsigned uses, UnaryOperatorType type, NOT_NULL(Expression) operand)
	: Expression(UnaryOperator, ctx, uses), type(type)
	{
		assert(uses == 1);
		setOperand(operand);
	}
	
	UnaryOperatorType getType() const { return type; }
	
	using ExpressionUser::getOperand;
	OPERAND_GET_SET(Operand, 0)
	
	virtual const ExpressionType& getExpressionType(AstContext& context) const override;
	virtual bool operator==(const Expression& that) const override;
};

// Represents a chain of the same binary operator. For instance, +(a, b, c) would be a + b + c.
class NAryOperatorExpression final : public Expression
{
	template<typename... TExpressionType>
	void setOperands(unsigned index, NOT_NULL(Expression) expr, TExpressionType&&... exprs)
	{
		setOperand(index, expr);
		setOperand(index + 1, std::forward<TExpressionType>(exprs)...);
	}
	
public:
	enum NAryOperatorType : unsigned
	{
		Min = UnaryOperatorExpression::Max,
		
		Assign = Min,
		Multiply, Divide, Modulus,
		Add, Subtract,
		ShiftLeft, ShiftRight,
		
		// The order of comparison operators is important. It must be possible to invert a comparison by flipping the
		// lowest bit of the operator type.
		ComparisonMin = (ShiftRight + 2) & ~1,
		SmallerThan = ComparisonMin,
		GreaterOrEqualTo,
		GreaterThan,
		SmallerOrEqualTo,
		Equal,
		NotEqual,
		ComparisonMax,
		
		BitwiseAnd = ComparisonMax,
		BitwiseXor,
		BitwiseOr,
		ShortCircuitAnd,
		ShortCircuitOr,
		
		Max
	};
	
private:
	NAryOperatorType type;
	
public:
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == NAryOperator;
	}
	
	NAryOperatorExpression(AstContext& ctx, unsigned uses, NAryOperatorType type)
	: Expression(NAryOperator, ctx, uses), type(type)
	{
		assert(uses > 0);
	}
	
	template<typename... TExpressionType>
	NAryOperatorExpression(AstContext& ctx, unsigned uses, NAryOperatorType type, TExpressionType... expressions)
	: Expression(NAryOperator, ctx, uses, sizeof...(TExpressionType)), type(type)
	{
		assert(uses >= sizeof...(TExpressionType));
		setOperand(0, expressions...);
	}
	
	NAryOperatorType getType() const { return type; }
	
	using ExpressionUser::setOperand;
	
	virtual const ExpressionType& getExpressionType(AstContext& context) const override;
	virtual bool operator==(const Expression& that) const override;
};

class MemberAccessExpression final : public Expression
{
	const StructExpressionType& structureType;
	unsigned fieldIndex;
	
	static std::pair<UserType, const StructExpressionType*> createInitInfo(AstContext& ctx, const Expression& base);
	
	MemberAccessExpression(AstContext& ctx, unsigned uses, NOT_NULL(Expression) base, std::pair<UserType, const StructExpressionType*> initInfo, unsigned fieldIndex)
	: Expression(initInfo.first, ctx, uses), structureType(*initInfo.second), fieldIndex(fieldIndex)
	{
		assert(uses == 1);
		assert(classof(this));
		setBaseExpression(base);
	}
	
public:
	enum MemberAccessType
	{
		PointerAccess = NAryOperatorExpression::Max,
		MemberAccess,
		Max,
	};
	
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == ExpressionUser::MemberAccess || node->getUserType() == ExpressionUser::PointerAccess;
	}
	
	MemberAccessExpression(AstContext& ctx, unsigned uses, NOT_NULL(Expression) base, unsigned fieldIndex)
	: MemberAccessExpression(ctx, uses, base, createInitInfo(ctx, *base), fieldIndex)
	{
	}
	
	MemberAccessType getAccessType() const
	{
		return getUserType() == ExpressionUser::MemberAccess
			? MemberAccessType::MemberAccess
			: MemberAccessType::PointerAccess;
	}
	
	unsigned getFieldIndex() const { return fieldIndex; }
	const std::string& getFieldName() const;
	
	OPERAND_GET_SET(BaseExpression, 0)
	
	virtual const ExpressionType& getExpressionType(AstContext& context) const override;
	virtual bool operator==(const Expression& that) const override;
};

class TernaryExpression final : public Expression
{
public:
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == Ternary;
	}
	
	TernaryExpression(AstContext& ctx, unsigned uses, NOT_NULL(Expression) condition, NOT_NULL(Expression) ifTrue, NOT_NULL(Expression) ifFalse)
	: Expression(Ternary, ctx, uses)
	{
		assert(uses == 3);
		setCondition(condition);
		setTrueValue(ifTrue);
		setFalseValue(ifFalse);
	}
	
	OPERAND_GET_SET(Condition, 0)
	OPERAND_GET_SET(TrueValue, 1)
	OPERAND_GET_SET(FalseValue, 2)
	
	virtual const ExpressionType& getExpressionType(AstContext& context) const override;
	virtual bool operator==(const Expression& that) const override;
};

struct NumericExpression final : public Expression
{
	const IntegerExpressionType& expressionType;
	union
	{
		int64_t si64;
		uint64_t ui64;
	};
	
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == Numeric;
	}
	
	NumericExpression(AstContext& ctx, unsigned uses, const IntegerExpressionType& type, uint64_t ui)
	: Expression(Numeric, ctx, uses), expressionType(type), ui64(ui)
	{
		assert(uses == 0);
	}
	
	NumericExpression(AstContext& ctx, unsigned uses, const IntegerExpressionType& type, int64_t si)
	: Expression(Numeric, ctx, uses), expressionType(type), si64(si)
	{
		assert(uses == 0);
	}
	
	virtual const IntegerExpressionType& getExpressionType(AstContext&) const override { return expressionType; }
	virtual bool operator==(const Expression& that) const override;
};

struct TokenExpression final : public Expression
{
	const ExpressionType& expressionType;
	NOT_NULL(const char) token;
	
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == Token;
	}
	
	TokenExpression(AstContext& ctx, unsigned uses, const ExpressionType& type, llvm::StringRef token);
	
	virtual const ExpressionType& getExpressionType(AstContext&) const override { return expressionType; }
	virtual bool operator==(const Expression& that) const override;
};

class CallExpression final : public Expression
{
public:
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == Call;
	}
	
	explicit CallExpression(AstContext& ctx, unsigned uses, NOT_NULL(Expression) callee)
	: Expression(Call, ctx, uses)
	{
		assert(uses > 0);
		setCallee(callee);
	}
	
	OPERAND_GET_SET(Callee, 0);
	
	ExpressionUse& getParameter(unsigned index) { return getOperandUse(index + 1); }
	const ExpressionUse& getParameter(unsigned index) const { return getOperandUse(index + 1); }
	void setParameter(unsigned index, NOT_NULL(Expression) param) { setOperand(index + 1, param); }
	
	unsigned params_size() const { return operands_size() - 1; }
	iterator params_begin();
	const_iterator params_begin() const;
	const_iterator params_cbegin() const { return params_begin(); }
	iterator params_end() { return operands_end(); }
	const_iterator params_end() const { return operands_end(); }
	const_iterator params_cend() const { return operands_end(); }
	llvm::iterator_range<iterator> params() { return llvm::make_range(params_begin(), params_end()); }
	llvm::iterator_range<const_iterator> params() const { return llvm::make_range(params_begin(), params_end()); }
	
	template<typename TIter>
	void addParameter(TIter begin, TIter end)
	{
		for (auto iter = begin; iter != end; ++iter)
		{
			addOperand(*iter);
		}
	}
	
	template<typename... TExpressionType>
	void addParameter(Expression* expression, TExpressionType... expressions)
	{
		addParameter(expression);
		addParameter(expressions...);
	}
	
	void addParameter(Expression* expression);
	
	virtual const ExpressionType& getExpressionType(AstContext&) const override;
	virtual bool operator==(const Expression& that) const override;
};

class CastExpression final : public Expression
{
	const ExpressionType& expressionType;
	
public:
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == Cast;
	}
	
	explicit CastExpression(AstContext& ctx, unsigned uses, const ExpressionType& type, NOT_NULL(Expression) value)
	: Expression(Cast, ctx, uses), expressionType(type)
	{
		assert(uses == 1);
		setCastValue(value);
	}
	
	OPERAND_GET_SET(CastValue, 0)
	
	virtual const ExpressionType& getExpressionType(AstContext&) const override { return expressionType; }
	virtual bool operator==(const Expression& that) const override;
};

class AggregateExpression final : public Expression
{
	const ExpressionType& expressionType;
	AstContext& ctx;
	
public:
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == Aggregate;
	}
	
	explicit AggregateExpression(AstContext& ctx, unsigned numUses, const ExpressionType& type)
	: Expression(Aggregate, ctx, numUses), expressionType(type), ctx(ctx)
	{
	}
	
	virtual bool operator==(const Expression& that) const override;
	
	virtual const ExpressionType& getExpressionType(AstContext&) const override { return expressionType; }
	AggregateExpression* copyWithNewItem(unsigned index, NOT_NULL(Expression) expression);
};

struct SubscriptExpression final : public Expression
{
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == Subscript;
	}
	
	SubscriptExpression(AstContext& ctx, unsigned uses, NOT_NULL(Expression) left, NOT_NULL(Expression) subscript)
	: Expression(Subscript, ctx, uses)
	{
		setPointer(left);
		setIndex(subscript);
	}
	
	OPERAND_GET_SET(Pointer, 0)
	OPERAND_GET_SET(Index, 1)
	
	virtual const ExpressionType& getExpressionType(AstContext&) const override;
	virtual bool operator==(const Expression& that) const override;
};

struct AssemblyExpression final : public Expression
{
	const PointerExpressionType& expressionType;
	NOT_NULL(const char) assembly;
	
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == Assembly;
	}
	
	AssemblyExpression(AstContext& ctx, unsigned uses, const FunctionExpressionType& type, llvm::StringRef assembly);
	
	const FunctionExpressionType& getFunctionType() const { return llvm::cast<FunctionExpressionType>(expressionType.getNestedType()); }
	virtual const PointerExpressionType& getExpressionType(AstContext&) const override { return expressionType; }
	virtual bool operator==(const Expression& that) const override;
};

struct AssignableExpression final : public Expression
{
	const ExpressionType& expressionType;
	NOT_NULL(const char) prefix;
	bool addressable;
	
	static bool classof(const ExpressionUser* node)
	{
		return node->getUserType() == Assignable;
	}
	
	AssignableExpression(AstContext& ctx, unsigned uses, const ExpressionType& type, llvm::StringRef prefix, bool addressable = false);
	
	virtual const ExpressionType& getExpressionType(AstContext&) const override { return expressionType; }
	virtual bool operator==(const Expression& that) const override;
};

#endif /* fcd__ast_expressions_h */
