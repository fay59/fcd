//
// clone.cpp
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

#include "clone.h"
#include "llvm_warnings.h"
#include "visitor.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/ErrorHandling.h>
SILENCE_LLVM_WARNINGS_END()

#include <deque>
#include <unordered_map>

using namespace llvm;
using namespace std;

namespace
{
	class ExpressionCloneVisitor : public AstVisitor<ExpressionCloneVisitor, true, NOT_NULL(Expression)>
	{
		AstContext& context;
		unordered_map<const Expression*, Expression*> clones;
		unordered_map<const ExpressionType*, const ExpressionType*> types;
		
		const ExpressionType& visitType(const ExpressionType& that)
		{
			auto& type = types[&that];
			if (type == nullptr)
			{
				if (isa<VoidExpressionType>(that))
				{
					type = &context.getVoid();
				}
				else if (auto intTy = dyn_cast<IntegerExpressionType>(&that))
				{
					type = &context.getIntegerType(intTy->isSigned(), intTy->getBits());
				}
				else if (auto pointerTy = dyn_cast<PointerExpressionType>(&that))
				{
					type = &context.getPointerTo(visitType(pointerTy->getNestedType()));
				}
				else if (auto arrayTy = dyn_cast<ArrayExpressionType>(&that))
				{
					type = &context.getArrayOf(arrayTy->getNestedType(), arrayTy->size());
				}
				else if (auto structTy = dyn_cast<StructExpressionType>(&that))
				{
					StructExpressionType& result = context.createStructure(structTy->getName());
					for (const auto& field : *structTy)
					{
						result.append(visitType(field.type), field.name);
					}
					type = &result;
				}
				else if (auto funcTy = dyn_cast<FunctionExpressionType>(&that))
				{
					FunctionExpressionType& result = context.createFunction(visitType(funcTy->getReturnType()));
					for (const auto& field : *funcTy)
					{
						result.append(visitType(field.type), field.name);
					}
					type = &result;
				}
				else
				{
					llvm_unreachable("unknown expression type");
				}
			}
			return *type;
		}
		
	public:
		ExpressionCloneVisitor(AstContext& context)
		: context(context)
		{
		}
		
		NOT_NULL(Expression) visit(const ExpressionUser& user)
		{
			if (auto expr = dyn_cast<Expression>(&user))
			{
				auto& clone = clones[expr];
				if (clone == nullptr)
				{
					clone = AstVisitor::visit(*expr);
				}
				return clone;
			}
			else
			{
				return AstVisitor::visit(user);
			}
		}
		
		NOT_NULL(Expression) visitUnaryOperator(const UnaryOperatorExpression& unary)
		{
			return context.unary(unary.getType(), visit(*unary.getOperand()));
		}
		
		NOT_NULL(Expression) visitNAryOperator(const NAryOperatorExpression& nary)
		{
			auto result = context.nary(nary.getType(), nary.operands_size());
			unsigned i = 0;
			for (const ExpressionUse& use : nary.operands())
			{
				result->setOperand(i, visit(*use.getUse()));
				++i;
			}
			return result;
		}
		
		NOT_NULL(Expression) visitMemberAccess(const MemberAccessExpression& memberAccess)
		{
			return context.memberAccess(visit(*memberAccess.getBaseExpression()), memberAccess.getFieldIndex());
		}
		
		NOT_NULL(Expression) visitTernary(const TernaryExpression& ternary)
		{
			return context.ternary(
				visit(*ternary.getCondition()),
				visit(*ternary.getTrueValue()),
				visit(*ternary.getFalseValue()));
		}
		
		NOT_NULL(Expression) visitNumeric(const NumericExpression& numeric)
		{
			const auto& intType = cast<IntegerExpressionType>(visitType(numeric.getExpressionType(context)));
			return context.numeric(intType, numeric.ui64);
		}
		
		NOT_NULL(Expression) visitToken(const TokenExpression& token)
		{
			SmallVector<Expression*, 3> builtinExpressions {
				context.expressionForUndef(),
				context.expressionForTrue(),
				context.expressionForNull(),
			};
			
			for (Expression* builtin : builtinExpressions)
			{
				if (token == *builtin)
				{
					return builtin;
				}
			}
			
			return context.token(visitType(token.getExpressionType(context)), &*token.token);
		}
		
		NOT_NULL(Expression) visitCall(const CallExpression& call)
		{
			auto result = context.call(visit(*call.getCallee()), call.params_size());
			unsigned i = 0;
			for (const ExpressionUse& use : call.params())
			{
				result->setParameter(i, visit(*use.getUse()));
				++i;
			}
			return result;
		}
		
		NOT_NULL(Expression) visitCast(const CastExpression& cast)
		{
			return context.cast(visitType(cast.getExpressionType(context)), visit(*cast.getCastValue()));
		}
		
		NOT_NULL(Expression) visitAggregate(const AggregateExpression& agg)
		{
			auto result = context.aggregate(visitType(agg.getExpressionType(context)), agg.operands_size());
			unsigned i = 0;
			for (const ExpressionUse& use : agg.operands())
			{
				result->setOperand(i, visit(*use.getUse()));
				++i;
			}
			return result;
		}
		
		NOT_NULL(Expression) visitSubscript(const SubscriptExpression& subscript)
		{
			return context.subscript(visit(*subscript.getPointer()), visit(*subscript.getIndex()));
		}
		
		NOT_NULL(Expression) visitAssembly(const AssemblyExpression& assembly)
		{
			const auto& functionType = cast<FunctionExpressionType>(visitType(assembly.getFunctionType()));
			return context.assembly(functionType, &*assembly.assembly);
		}
		
		NOT_NULL(Expression) visitAssignable(const AssignableExpression& assignable)
		{
			return context.assignable(visitType(assignable.getExpressionType(context)), &*assignable.prefix);
		}
		
		NOT_NULL(Expression) visitDefault(const ExpressionUser& user)
		{
			llvm_unreachable("unimplemented expression clone case");
		}
	};
	
	class StatementCloneVisitor : public AstVisitor<StatementCloneVisitor, true, Statement*>
	{
		AstContext& ctx;
		ExpressionCloneVisitor expressionCloner;
		
	public:
		StatementCloneVisitor(AstContext& ctx)
		: ctx(ctx), expressionCloner(ctx)
		{
		}
		
		Statement* visitNoop(const NoopStatement& noop)
		{
			return ctx.noop();
		}
		
		Statement* visitSequence(const SequenceStatement& sequence)
		{
			auto result = ctx.sequence();
			for (const Statement* statement : sequence)
			{
				result->pushBack(visit(*statement));
			}
			return result;
		}
		
		Statement* visitIfElse(const IfElseStatement& ifElse)
		{
			auto condition = expressionCloner.visit(*ifElse.getCondition());
			auto ifBody = visit(*ifElse.getIfBody());
			Statement* elseBody = nullptr;
			if (auto oldBody = ifElse.getElseBody())
			{
				elseBody = visit(*oldBody);
			}
			return ctx.ifElse(condition, ifBody, elseBody);
		}
		
		Statement* visitLoop(const LoopStatement& loop)
		{
			auto condition = expressionCloner.visit(*loop.getCondition());
			auto loopBody = visit(*loop.getLoopBody());
			return ctx.loop(condition, loop.getPosition(), loopBody);
		}
		
		Statement* visitKeyword(const KeywordStatement& keyword)
		{
			Expression* cloned = nullptr;
			if (auto expression = keyword.getOperand())
			{
				cloned = expressionCloner.visit(*expression);
			}
			return ctx.keyword(&*keyword.name, cloned);
		}
		
		Statement* visitExpr(const ExpressionStatement& expression)
		{
			return ctx.expr(expressionCloner.visit(*expression.getExpression()));
		}
		
		Statement* visitDefault(const ExpressionUser& user)
		{
			llvm_unreachable("unimplemented expression clone case");
		}
	};
}

NOT_NULL(Expression) CloneVisitor::clone(AstContext& context, const Expression& toClone)
{
	return ExpressionCloneVisitor(context).visit(toClone);
}

NOT_NULL(Statement) CloneVisitor::clone(AstContext& context, const Statement& toClone)
{
	return StatementCloneVisitor(context).visit(toClone);
}

NOT_NULL(ExpressionUser) CloneVisitor::clone(AstContext& context, const ExpressionUser& toClone)
{
	if (auto expr = dyn_cast<Expression>(&toClone))
	{
		return &*clone(context, *expr);
	}
	else
	{
		return &*clone(context, cast<Statement>(toClone));
	}
}
