//
// visitor.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
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
			SWITCH_CASE(Expression, MemberAccess);
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
	DELEGATE_CALL(Expression, MemberAccess)
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
	
	// Called when nothing else matches.
	// not implemented: needs to have an implementation in the subclass
	ReturnType visitDefault(OptionallyConst<UsesConst, ExpressionUser>& user);
};

#undef DELEGATE_CALL
#undef SWITCH_CASE

#endif /* fcd__ast_visitor_h */
