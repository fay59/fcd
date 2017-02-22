//
// symbolic_expr.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__callconv_symbolic_expr_h
#define fcd__callconv_symbolic_expr_h

#include "dumb_allocator.h"
#include "targetinfo.h"

#include <llvm/ADT/APInt.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>

namespace symbolic
{
	class Expression
	{
	protected:
		enum ExpressionKind
		{
			LiveOnEntry,
			Load,
			ConstantInt,
			Add,
			Negate,
		};
		
		inline explicit Expression(ExpressionKind kind)
		: kind(kind)
		{
		}
		
	private:
		ExpressionKind kind;
		
	public:
		inline ExpressionKind getKind() const
		{
			return kind;
		}
		
		virtual void print(llvm::raw_ostream&) const = 0;
		void dump() const;
	};

	class LiveOnEntryExpression : public Expression
	{
		const TargetRegisterInfo* registerInfo;
		
	public:
		inline explicit LiveOnEntryExpression(const TargetRegisterInfo* registerInfo)
		: Expression(Expression::LiveOnEntry), registerInfo(registerInfo)
		{
		}
		
		inline const TargetRegisterInfo* getRegisterInfo() const { return registerInfo; }
		
		static inline bool classof(const Expression* x)
		{
			return x->getKind() == Expression::LiveOnEntry;
		}
		
		virtual void print(llvm::raw_ostream&) const override;
	};

	class LoadExpression : public Expression
	{
		Expression* address;
		
	public:
		inline explicit LoadExpression(Expression* address)
		: Expression(Expression::Load), address(address)
		{
			assert(address != nullptr);
		}
		
		inline Expression* getAddress() { return address; }
		
		static inline bool classof(const Expression* x)
		{
			return x->getKind() == Expression::Load;
		}
		
		virtual void print(llvm::raw_ostream&) const override;
	};

	class ConstantIntExpression : public Expression
	{
		int64_t value;
		
	public:
		inline explicit ConstantIntExpression(int64_t value)
		: Expression(Expression::ConstantInt), value(value)
		{
		}
		
		inline int64_t getValue() const { return value; }
		
		static inline bool classof(const Expression* x)
		{
			return x->getKind() == Expression::ConstantInt;
		}
		
		virtual void print(llvm::raw_ostream&) const override;
	};

	class AddExpression : public Expression
	{
	private:
		Expression* left;
		Expression* right;
		
	public:
		inline explicit AddExpression(Expression* left, Expression* right)
		: Expression(Expression::Add), left(left), right(right)
		{
			assert(left != nullptr);
			assert(right != nullptr);
		}
		
		inline Expression* getLeft() { return left; }
		inline Expression* getRight() { return right; }
		
		static inline bool classof(const Expression* x)
		{
			return x->getKind() == Expression::Add;
		}
		
		virtual void print(llvm::raw_ostream&) const override;
	};

	class NegateExpression : public Expression
	{
		Expression* negated;
		
	public:
		inline explicit NegateExpression(Expression* negate)
		: Expression(Expression::Negate), negated(negate)
		{
			assert(negated != nullptr);
		}
		
		inline Expression* getNegated() { return negated; }
		
		static inline bool classof(const Expression* x)
		{
			return x->getKind() == Expression::Negate;
		}
		
		virtual void print(llvm::raw_ostream&) const override;
	};

	class ExpressionContext
	{
		DumbAllocator pool;
		
	public:
		inline AddExpression* createAdd(Expression* left, Expression* right)
		{
			return pool.allocate<AddExpression>(left, right);
		}
		
		inline NegateExpression* createNegate(Expression* operand)
		{
			return pool.allocate<NegateExpression>(operand);
		}
		
		inline ConstantIntExpression* createConstant(int64_t value)
		{
			return pool.allocate<ConstantIntExpression>(value);
		}
		
		inline ConstantIntExpression* createConstant(const llvm::APInt& value)
		{
			return createConstant(static_cast<int64_t>(value.getLimitedValue()));
		}
		
		inline LoadExpression* createLoad(Expression* expr)
		{
			return pool.allocate<LoadExpression>(expr);
		}
		
		inline LiveOnEntryExpression* createLiveOnEntry(const TargetRegisterInfo* info)
		{
			return pool.allocate<LiveOnEntryExpression>(info);
		}
		
		Expression* simplify(Expression* that);
	};
}

#endif /* defined(fcd__callconv_symbolic_expr_h) */
