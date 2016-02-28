//
// visitor.h
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

#ifndef fcd__ast_visitor_h
#define fcd__ast_visitor_h

#include "ast_context.h"

#define DELEGATE_CALL(suffix, type) \
	ReturnType visit##type(OptionallyConst<UsesConst, type##suffix>& o) { return d().visit##suffix(o); }

#define SWITCH_CASE(suffix, type) \
	case ExpressionUser::type: \
	return d().visit##type(llvm::cast<type##suffix>(user))

template<typename Derived, bool UsesConst = true, typename ReturnType = void>
class AstVisitor
{
	template<bool B, typename T>
	using OptionallyConst = typename std::conditional<B, typename std::add_const<T>::type, typename std::remove_const<T>::type>::type;
	
	Derived& d() { return *static_cast<Derived*>(this); }
	
public:
	ReturnType visit(OptionallyConst<UsesConst, ExpressionUser>& user)
	{
		switch (user.getUserType())
		{
			SWITCH_CASE(Statement, Noop);
			SWITCH_CASE(Statement, Sequence);
			SWITCH_CASE(Statement, IfElse);
			SWITCH_CASE(Statement, Loop);
			SWITCH_CASE(Statement, Keyword);
				
			SWITCH_CASE(Expression, Token);
			SWITCH_CASE(Expression, Numeric);
			SWITCH_CASE(Expression, UnaryOperator);
			SWITCH_CASE(Expression, NAryOperator);
			SWITCH_CASE(Expression, Call);
			SWITCH_CASE(Expression, Cast);
			SWITCH_CASE(Expression, Ternary);
			SWITCH_CASE(Expression, Aggregate);
			SWITCH_CASE(Expression, Subscript);
			SWITCH_CASE(Expression, Assembly);
			SWITCH_CASE(Expression, Assignable);
			
			case ExpressionUser::Expr:
				return d().visitExpr(llvm::cast<ExpressionStatement>(user));
			default:
				return d().visitDefault(user);
		}
	}
	
	DELEGATE_CALL(Statement, Noop)
	DELEGATE_CALL(Statement, Sequence)
	DELEGATE_CALL(Statement, IfElse)
	DELEGATE_CALL(Statement, Loop)
	DELEGATE_CALL(Statement, Keyword)
	
	ReturnType visitExpr(OptionallyConst<UsesConst, ExpressionStatement>& expr) { return d().visitStatement(expr); }
	
	DELEGATE_CALL(Expression, Token)
	DELEGATE_CALL(Expression, Numeric)
	DELEGATE_CALL(Expression, UnaryOperator)
	DELEGATE_CALL(Expression, NAryOperator)
	DELEGATE_CALL(Expression, Call)
	DELEGATE_CALL(Expression, Cast)
	DELEGATE_CALL(Expression, Ternary)
	DELEGATE_CALL(Expression, Aggregate)
	DELEGATE_CALL(Expression, Subscript)
	DELEGATE_CALL(Expression, Assembly)
	DELEGATE_CALL(Expression, Assignable)
	
	ReturnType visitStatement(OptionallyConst<UsesConst, Statement>& statement)
	{
		return d().visitDefault(statement);
	}
	
	ReturnType visitExpression(OptionallyConst<UsesConst, Expression>& expression)
	{
		return d().visitDefault(expression);
	}
	
	// not implemented: needs to have an implementation in the subclass
	ReturnType visitDefault(OptionallyConst<UsesConst, ExpressionUser>& user);
};

#undef DELEGATE_CALL
#undef SWITCH_CASE

#endif /* fcd__ast_visitor_h */
