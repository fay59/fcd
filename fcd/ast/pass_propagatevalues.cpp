//
// pass_propagatevalues.cpp
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

//
// In the AST context, propagating an expression means removing the variable
// it's assigned to, and replacing the use(s) of that variable with the
// expression itself.
//
// You should only propagate an expression when the receiving variable has only
// one assignment. The SSA form we come from ensures that this is usually the
// case (notable exceptions being PHI nodes and stores). Additionally,
// expressions should only be propagated if:
//
// 1- it is used only once;
// 2- it doesn't have the isBarrier attribute;
// 3- it has the isBarrier attribute, but it's not being moved across another
//    barrier.
//
// The barrier attribute is set on expressions created from memory instructions
// (loads, stores, calls) because their relative ordering is usually important.
//
// So, we need to keep track of:
//
// - where each expression is used (and, trivially, how many times it is used);
// - when an expression is being assigned to;
// - where are barrier expressions located.
//

#include "clone.h"
#include "pass_propagatevalues.h"
#include "visitor.h"

#include <set>
#include <unordered_map>
#include <vector>

using namespace llvm;
using namespace std;

namespace
{
	struct VariableInfo
	{
		Expression* variable;
		//SmallVector<size_t, 1> assignedValues;
		//SmallVector<size_t, 4> uses;
		vector<pair<AssignmentStatement*, size_t>> assignedValues;
		vector<size_t> uses;
		
		VariableInfo()
		: variable(nullptr)
		{
		}
	};
	
	// Can't use ExpressionVisitor because we need references to the object pointers.
	struct ValuePropagationState : public StatementVisitor
	{
		unordered_map<Expression*, VariableInfo> info;
		vector<Expression**> indexedExpressions;
		set<size_t> barriers;
		
		virtual void visitIfElse(IfElseStatement* ifElse) override
		{
			visitNNExpression(ifElse->condition);
			return StatementVisitor::visitIfElse(ifElse);
		}
		
		virtual void visitLoop(LoopStatement* loop) override
		{
			visitNNExpression(loop->condition);
			return StatementVisitor::visitLoop(loop);
		}
		
		virtual void visitKeyword(KeywordStatement* kw) override
		{
			if (kw->operand != nullptr)
			{
				visitExpression(kw->operand);
			}
			return StatementVisitor::visitKeyword(kw);
		}
		
		virtual void visitExpression(ExpressionStatement* expr) override
		{
			visitNNExpression(expr->expression);
			return StatementVisitor::visitExpression(expr);
		}
		
		virtual void visitAssignment(AssignmentStatement* assignment) override
		{
			VariableInfo& variable = info[assignment->left];
			variable.variable = assignment->left;
			
			visitNNExpression(assignment->right);
			size_t assignmentIndex = indexedExpressions.size() - 1;
			variable.assignedValues.push_back({assignment, assignmentIndex});
			
			visitNNExpression(assignment->left);
			variable.uses.pop_back();
			
			return StatementVisitor::visitAssignment(assignment);
		}
		
		// depth-first expression visitation
		void visitNNExpression(NOT_NULL(Expression)& expression)
		{
			visitExpression(*addressOf(expression));
		}
		
		void visitExpression(Expression*& expression)
		{
			
#define TYPE_CASE_2(enumValue, type) \
	case Expression::enumValue: \
		visit##enumValue(static_cast<type*>(expression)); \
		break
			
#define TYPE_CASE(enumValue) TYPE_CASE_2(enumValue, enumValue##Expression)
			
			switch (expression->getType())
			{
				TYPE_CASE_2(UnaryOperator, UnaryOperatorExpression);
				TYPE_CASE_2(NAryOperator, NAryOperatorExpression);
				TYPE_CASE(Ternary);
				TYPE_CASE(Numeric);
				TYPE_CASE(Token);
				TYPE_CASE(Call);
				TYPE_CASE(Cast);
				TYPE_CASE(Aggregate);
				TYPE_CASE(Subscript);
			}
			
#undef TYPE_CASE
			
			size_t thisIndex = indexedExpressions.size();
			indexedExpressions.push_back(&expression);
			if (expression->isBarrier)
			{
				barriers.insert(thisIndex);
			}
			
			auto iter = info.find(expression);
			if (iter != info.end())
			{
				iter->second.uses.push_back(thisIndex);
			}
		}
		
		void visitUnaryOperator(UnaryOperatorExpression* unary)
		{
			visitNNExpression(unary->operand);
		}
		
		void visitNAryOperator(NAryOperatorExpression* nary)
		{
			for (NOT_NULL(Expression)& expr : nary->operands)
			{
				visitNNExpression(expr);
			}
		}
		
		void visitTernary(TernaryExpression* expr)
		{
			visitNNExpression(expr->ifFalse);
			visitNNExpression(expr->ifTrue);
			visitNNExpression(expr->condition);
		}
		
		void visitNumeric(NumericExpression* expr)
		{
		}
		
		void visitToken(TokenExpression* expr)
		{
		}
		
		void visitCall(CallExpression* expr)
		{
			// XXX: in real C, evaluation order of arguments is unspecified,
			// but here we set barriers in left-to-right order.
			for (NOT_NULL(Expression)& expr : expr->parameters)
			{
				visitNNExpression(expr);
			}
		}
		
		void visitCast(CastExpression* expr)
		{
			visitNNExpression(expr->casted);
		}
		
		void visitAggregate(AggregateExpression* expr)
		{
			// XXX: in real C, evaluation order of arguments is unspecified,
			// but here we set barriers in left-to-right order.
			for (NOT_NULL(Expression)& expr : expr->values)
			{
				visitNNExpression(expr);
			}
		}
		
		void visitSubscript(SubscriptExpression* expr)
		{
			visitNNExpression(expr->index);
			visitNNExpression(expr->left);
		}
	};
}

void AstPropagateValues::doRun(FunctionNode &fn)
{
	ValuePropagationState state;
	fn.body->visit(state);
	
	auto infoEnd = state.info.end();
	for (size_t j = state.indexedExpressions.size(); j > 0; --j)
	{
		size_t i = j - 1;
		Expression*& expr = *state.indexedExpressions[i];
		auto iter = state.info.find(expr);
		if (iter != infoEnd)
		{
			auto& info = iter->second;
			if (info.assignedValues.size() == 1 && info.uses.size() == 1)
			{
				AssignmentStatement* assignment = info.assignedValues[0].first;
				size_t assignmentIndex = info.assignedValues[0].second;
				Expression*& replaceWith = *state.indexedExpressions[assignmentIndex];
				if (expr == replaceWith)
				{
					// don't bother for that
					continue;
				}
				
				// also don't bother to the left-hand side of an assignment
				if (addressOf(assignment->left) == &expr)
				{
					continue;
				}
				
				// is there a barrier in between?
				if (replaceWith->isBarrier)
				{
					auto rangeStart = state.barriers.upper_bound(assignmentIndex);
					auto rangeEnd = state.barriers.lower_bound(i);
					if (rangeStart != rangeEnd)
					{
						// there is a barrier in between.
						continue;
					}
				}
				
				// expression is safe to propagate
				expr = replaceWith;
				replaceWith = TokenExpression::undefExpression;
			}
		}
	}
}

const char* AstPropagateValues::getName() const
{
	return "Propagate values";
}
