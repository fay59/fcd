//
// symbolic_expr.h
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

#ifndef __x86Emulator__symbolic_expr__
#define __x86Emulator__symbolic_expr__

#include "dumb_allocator.h"
#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/APInt.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <list>
#include <type_traits>

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
		const char* registerName;
		
	public:
		inline explicit LiveOnEntryExpression(const char* registerName)
		: Expression(Expression::LiveOnEntry), registerName(registerName)
		{
		}
		
		inline const char* getRegisterName() const { return registerName; }
		
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
		
		inline ConstantIntExpression* createConstant(uint64_t value)
		{
			return pool.allocate<ConstantIntExpression>(value);
		}
		
		inline ConstantIntExpression* createConstant(const llvm::APInt& value)
		{
			return createConstant(value.getLimitedValue());
		}
		
		inline LoadExpression* createLoad(Expression* expr)
		{
			return pool.allocate<LoadExpression>(expr);
		}
		
		inline LiveOnEntryExpression* createLiveOnEntry(const char* name)
		{
			return pool.allocate<LiveOnEntryExpression>(name);
		}
		
		Expression* simplify(Expression* that);
	};
}

#endif /* defined(__x86Emulator__symbolic_expr__) */
