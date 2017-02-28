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
		size_t operator()(const CongruenceCandidate& that) const
		{
			return hash<Expression*>()(that.left) ^ hash<Expression*>()(that.right);
		}
	};
}

namespace
{
	class AssignableUseDef
	{
		PointerIntPair<ExpressionUse*, 1> use;
		
	public:
		AssignableUseDef(ExpressionUse* use)
		: use(use)
		{
		}
		
		ExpressionUse* get() { return use.getPointer(); }
		Expression* getExpression() { return get()->getUse(); }
		bool isDef() { return use.getInt(); }
		bool isUse() { return !isDef(); }
		void setDef() { use.setInt(1); }
	};
	
	class UsingStatement : public AssignableUseDef
	{
		NOT_NULL(Statement) statement;
		
	public:
		UsingStatement(AssignableUseDef useDef, NOT_NULL(Statement) statement)
		: AssignableUseDef(useDef), statement(statement)
		{
		}
		
		Statement* getStatement() { return statement; }
	};
	
	LoopStatement* getParentLoop(NOT_NULL(Statement) statement)
	{
		for (Statement* parent = statement->getParent(); parent != nullptr; parent = parent->getParent())
		{
			if (auto loop = dyn_cast<LoopStatement>(parent))
			{
				return loop;
			}
		}
		return nullptr;
	}
	
	bool isEpxpressionAddressable(NOT_NULL(Expression) expr)
	{
		if (auto assignable = dyn_cast<AssignableExpression>(expr))
		{
			return assignable->addressable;
		}
		return true;
	}
	
	void mergeVariables(AstContext& ctx, Expression* toReplace, Expression* replaceWith)
	{
		while (!toReplace->uses_empty())
		{
			auto& use = *toReplace->uses_begin();
			if (auto assignment = dyn_cast<NAryOperatorExpression>(use.getUser()))
			if (assignment->getType() == NAryOperatorExpression::Assign)
			{
				// if we have `toReplace = replaceWith`, we need to remove the assignment entirely.
				SmallVector<Expression*, 2> assignmentOperands(assignment->operands_begin(), assignment->operands_end());
				auto replaceWithIter = find(assignmentOperands, replaceWith);
				auto toReplaceIter = find(assignmentOperands, toReplace);
				if (replaceWithIter != assignmentOperands.end() && replaceWithIter < toReplaceIter)
				{
					assignmentOperands.erase(toReplaceIter);
					if (assignmentOperands.size() == 1)
					{
						for (auto& use : assignment->uses())
						{
							auto assignmentStatement = cast<ExpressionStatement>(use.getUser());
							if (auto parent = assignmentStatement->getParent())
							{
								parent->replaceChild(assignmentStatement, ctx.noop());
							}
						}
					}
					else
					{
						auto newAssignment = ctx.nary(NAryOperatorExpression::Assign, assignmentOperands.begin(), assignmentOperands.end());
						assignment->replaceAllUsesWith(newAssignment);
					}
				}
			}
			
			// Replace use regardless of whether we also dropped assignment because uses linger around.
			use.setUse(replaceWith);
		}
	}
	
	class LivenessAnalysis
	{
		unordered_map<Expression*, SmallVector<UsingStatement, 16>> usingStatements;
		unordered_set<CongruenceCandidate> candidates;
		unordered_map<Statement*, size_t> statementStartIndices;
		unordered_map<Statement*, size_t> statementEndIndices;
		deque<Statement*> flatStatements;
		Statement* root;
		
		// intermediate dictionary, gets cleared at some point
		unordered_map<Expression*, SmallVector<AssignableUseDef, 16>> usesDefs;
		
		bool isRooted(NOT_NULL(Statement) statement)
		{
			for (Statement* stmt = statement; stmt != nullptr; stmt = stmt->getParent())
			{
				if (stmt == root)
				{
					return true;
				}
			}
			return false;
		}
		
		unordered_set<Statement*> getStatements(ExpressionUse& expressionUse)
		{
			auto topLevelUser = expressionUse.getUser();
			if (auto topLevelStatement = dyn_cast<Statement>(topLevelUser))
			{
				if (isRooted(topLevelStatement))
				{
					return { topLevelStatement };
				}
				return {};
			}
			
			unordered_set<Statement*> statements;
			unordered_set<Expression*> parents { cast<Expression>(topLevelUser) };
			unordered_set<Expression*> visited;
			
			while (parents.size() > 0)
			{
				auto parentIter = parents.begin();
				Expression* parent = *parentIter;
				parents.erase(parentIter);
				
				for (ExpressionUse& use : parent->uses())
				{
					ExpressionUser* user = use.getUser();
					if (auto stmt = dyn_cast<Statement>(user))
					{
						if (isRooted(stmt))
						{
							statements.insert(stmt);
						}
					}
					else
					{
						Expression* parentExpr = cast<Expression>(user);
						if (visited.count(parentExpr) == 0)
						{
							parents.insert(parentExpr);
						}
					}
				}
			}
			
			return statements;
		}
		
		Expression* collectAssignments(Statement* statement, ExpressionUser::iterator iter, ExpressionUser::iterator end)
		{
			ExpressionUse& thisExpressionUse = *iter;
			++iter;
			if (iter != end)
			{
				Expression* subAssignment = collectAssignments(statement, iter, end);
				
				auto result = usesDefs.insert({thisExpressionUse, {}});
				if (result.second)
				{
					for (ExpressionUse& use : thisExpressionUse.getUse()->uses())
					{
						result.first->second.emplace_back(&use);
					}
				}
				
				for (auto& useDef : result.first->second)
				{
					if (useDef.get() == &thisExpressionUse)
					{
						useDef.setDef();
						break;
					}
				}
				
				if (usesDefs.count(subAssignment))
				{
					candidates.insert({subAssignment, thisExpressionUse.getUse()});
				}
			}
			return thisExpressionUse;
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
			auto result = statementStartIndices.insert({&statement, flatStatements.size()});
			assert(result.second); (void) result;
			flatStatements.push_back(&statement);
			
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
			
			result = statementEndIndices.insert({&statement, flatStatements.size()});
			assert(result.second); (void) result;
		}
		
		bool compareUseDefWithIndex(size_t index, UsingStatement& statement)
		{
			return index < statementStartIndices.at(statement.getStatement());
		}
		
		bool liveRangeContains(Expression* liveVariable, Statement* stmt)
		{
			// At or after stmt, is there at least one more use of liveVariable before its next def?
			auto upperBoundComparator = bind(&LivenessAnalysis::compareUseDefWithIndex, this, placeholders::_1, placeholders::_2);
			auto& varUsers = usingStatements.at(liveVariable);
			size_t statementIndex = statementStartIndices.at(stmt);
			auto nextUseDef = upper_bound(varUsers.begin(), varUsers.end(), statementIndex, upperBoundComparator);
			
			if (nextUseDef != varUsers.end() && nextUseDef->isUse())
			{
				// Yes, there's a reachable use.
				return true;
			}
			
			// Linearly, there is no next use/def or the next use/def is a def. Check if stmt is inside a loop and
			// see if the previous definition could reach a use at the start of the loop.
			for (auto parentLoop = getParentLoop(stmt); parentLoop != nullptr; parentLoop = getParentLoop(parentLoop))
			{
				// See if there's a use between the original statement and the end of the loop.
				auto useDefBeforeLoopEnd = lower_bound(varUsers.begin(), nextUseDef, statementEndIndices.at(parentLoop), [=](UsingStatement& statement, size_t index)
				{
					return statementStartIndices.at(statement.getStatement()) < index;
				});
				
				if (useDefBeforeLoopEnd != varUsers.begin())
				{
					--useDefBeforeLoopEnd;
					if (statementStartIndices.at(useDefBeforeLoopEnd->getStatement()) > statementIndex)
					{
						return useDefBeforeLoopEnd->isUse();
					}
				}
				
				// See if there's a use between the start of the loop and the original statement.
				auto useDefAfterLoopStart = upper_bound(varUsers.begin(), nextUseDef, statementStartIndices.at(parentLoop), upperBoundComparator);
				if (useDefAfterLoopStart != nextUseDef)
				{
					if (statementStartIndices.at(useDefBeforeLoopEnd->getStatement()) < statementIndex)
					{
						return useDefAfterLoopStart->isUse();
					}
				}
			}
			
			return false;
		}
		
		bool interferenceFree(Expression* a, Expression* b)
		{
			return !any_of(usingStatements.at(b), [=](UsingStatement& useDef)
			{
				if (useDef.isDef())
				{
					Statement* statement = useDef.getStatement();
					return liveRangeContains(a, statement) && !assignmentAssigns(statement, b, a);
				}
				return false;
			});
		}
		
	public:
		void collectStatementIndices(FunctionNode& function)
		{
			usingStatements.clear();
			candidates.clear();
			statementStartIndices.clear();
			statementEndIndices.clear();
			flatStatements.clear();
			root = function.getBody();
			
			collectStatementIndices(*function.getBody());
			for (auto& pair : usesDefs)
			{
				auto& statements = usingStatements[pair.first];
				for (AssignableUseDef useDef : pair.second)
				{
					auto useDefStatements = getStatements(*useDef.get());
					assert(useDef.isUse() || useDefStatements.size() == 1);
					for (Statement* statement : useDefStatements)
					{
						statements.emplace_back(useDef, statement);
					}
				}
				
				sort(statements.begin(), statements.end(), [=](UsingStatement& a, UsingStatement& b)
				{
					size_t aIndex = statementStartIndices.at(a.getStatement());
					size_t bIndex = statementStartIndices.at(b.getStatement());
					if (aIndex < bIndex)
					{
						return true;
					}
					if (aIndex > bIndex)
					{
						return false;
					}
					return a.isUse() < b.isUse();
				});
			}
			usesDefs.clear();
		}
		
		const unordered_set<CongruenceCandidate>& getCandidates() const
		{
			return candidates;
		}
		
		bool congruent(Expression* a, Expression* b)
		{
			return interferenceFree(a, b) && interferenceFree(b, a);
		}
	};
}

void AstMergeCongruentVariables::doRun(FunctionNode &fn)
{
	LivenessAnalysis liveness;
	liveness.collectStatementIndices(fn);
	for (auto candidate : liveness.getCandidates())
	{
		if (liveness.congruent(candidate.left, candidate.right))
		{
			if (!isEpxpressionAddressable(candidate.left))
			{
				mergeVariables(context(), candidate.left, candidate.right);
			}
			else if (!isEpxpressionAddressable(candidate.right))
			{
				mergeVariables(context(), candidate.right, candidate.left);
			}
		}
	}
}

const char* AstMergeCongruentVariables::getName() const
{
	return "Merge Congruent Variables";
}
