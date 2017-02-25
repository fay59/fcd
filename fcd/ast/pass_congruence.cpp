//
// pass_congruence.cpp
// Copyright (C) 2017 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "ast_passes.h"
#include "visitor.h"

#include <llvm/ADT/SmallVector.h>

#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace llvm;
using namespace std;

namespace
{
	struct CongruenceCandidate
	{
		NOT_NULL(Expression) left;
		NOT_NULL(Expression) right;
		
		CongruenceCandidate(NOT_NULL(Expression) left, NOT_NULL(Expression) right)
		: left(left), right(right)
		{
		}
		
		bool operator==(const CongruenceCandidate& that) const
		{
			return (left == that.left && right == that.right) || (left == that.right && right == that.left);
		}
	};
}

namespace std
{
	template<>
	struct hash<CongruenceCandidate>
	{
		size_t operator()(const CongruenceCandidate& that)
		{
			return hash<Expression*>()(that.left) ^ hash<Expression*>()(that.right);
		}
	};
}

namespace
{
	class LivenessAnalysis
	{
		unordered_map<Expression*, SmallVector<Statement*, 4>> defs;
		unordered_set<CongruenceCandidate> candidates;
		unordered_map<Statement*, size_t> statementIndices;
		
		Expression* collectAssignments(Statement* statement, ExpressionUser::iterator iter, ExpressionUser::iterator end)
		{
			Expression* thisExpression = *iter;
			++iter;
			if (iter != end)
			{
				Expression* subAssignment = collectAssignments(statement, iter, end);
				defs[thisExpression].push_back(statement);
				if (defs.count(subAssignment))
				{
					candidates.insert({subAssignment, thisExpression});
				}
			}
			return thisExpression;
		}
		
		bool assignmentAssigns(Statement* assignment, Expression* left, Expression* right)
		{
			auto assignmentExpression = cast<ExpressionStatement>(assignment)->getExpression();
			if (auto nary = dyn_cast<NAryOperatorExpression>(assignmentExpression))
			if (nary->getType() == NAryOperatorExpression::Assign)
			{
				auto end = nary->operands_end();
				auto leftIter = find(nary->operands_begin(), end, left);
				if (leftIter != end)
				{
					++leftIter;
					return find(leftIter, end, right) != end;
				}
			}
			return false;
		}
		
		void collectStatementIndices(Statement& statement)
		{
			auto result = statementIndices.insert({&statement, statementIndices.size()});
			assert(result.second); (void) result;
			
			switch (statement.getUserType())
			{
				case ExpressionUser::Sequence:
				{
					for (auto statement : cast<SequenceStatement>(statement))
					{
						collectStatementIndices(*statement);
					}
					break;
				}
					
				case ExpressionUser::IfElse:
				{
					auto ifElse = cast<IfElseStatement>(statement);
					collectStatementIndices(*ifElse.getIfBody());
					if (auto elseBody = ifElse.getElseBody())
					{
						collectStatementIndices(*elseBody);
					}
					break;
				}
					
				case ExpressionUser::Loop:
				{
					collectStatementIndices(*cast<LoopStatement>(statement).getLoopBody());
					break;
				}
					
				case ExpressionUser::Expr:
				{
					auto expr = cast<ExpressionStatement>(statement).getExpression();
					if (auto assignment = dyn_cast<NAryOperatorExpression>(expr))
					if (assignment->getType() == NAryOperatorExpression::Assign)
					{
						collectAssignments(&statement, assignment->operands_begin(), assignment->operands_end());
					}
					break;
				}
					
				case ExpressionUser::Noop:
				case ExpressionUser::Keyword:
					break;
				default:
					llvm_unreachable("Unknown statement type!");
			}
		}
		
		bool statementLess(Statement* a, Statement* b)
		{
			return statementIndices.at(a) < statementIndices.at(b);
		}
		
		bool liveRangeContains(Expression* liveVariable, Statement* stmt)
		{
			// At or after stmt, is there at least one more use of liveVariable before its next def?
			return true;
		}
		
		bool interferenceFree(Expression* a, Expression* b)
		{
			return !any_of(defs.at(b), [=](Statement* def)
			{
				return liveRangeContains(a, def) && !assignmentAssigns(def, b, a);
			});
		}
		
		bool congruent(Expression* a, Expression* b)
		{
			return interferenceFree(a, b) && interferenceFree(b, a);
		}
		
	public:
		void collectStatementIndices(FunctionNode& function)
		{
			defs.clear();
			candidates.clear();
			statementIndices.clear();
			collectStatementIndices(*function.getBody());
			
			// collect uses
		}
	};
}

void AstMergeCongruentVariables::doRun(FunctionNode &fn)
{
	
}

const char* AstMergeCongruentVariables::getName() const
{
	return "Merge Congruent Variables";
}
