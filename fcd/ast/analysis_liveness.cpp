//
//  analysis_liveness.cpp
//  fcd
//
//  Created by Félix Cloutier on 30/03/2017.
//  Copyright © 2017 Félix Cloutier. All rights reserved.
//

#include "analysis_liveness.h"
#include "function.h"

using namespace llvm;
using namespace std;

namespace
{
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
}

unordered_set<Statement*> LivenessAnalysis::getStatements(ExpressionUse& expressionUse)
{
	auto topLevelUser = expressionUse.getUser();
	if (auto topLevelStatement = dyn_cast<Statement>(topLevelUser))
	{
		return { topLevelStatement };
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
				statements.insert(stmt);
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

void LivenessAnalysis::collectAssignments(Statement *statement, ExpressionUser::iterator iter, ExpressionUser::iterator end)
{
	ExpressionUse& thisExpressionUse = *iter;
	++iter;
	if (iter != end)
	{
		collectAssignments(statement, iter, end);
		
		auto result = usesDefs.insert({thisExpressionUse, {}});
		if (result.second)
		{
			assignedExpressions.push_back(thisExpressionUse);
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
	}
}

bool LivenessAnalysis::assignmentAssigns(Statement *assignment, Expression *left, Expression *right)
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

void LivenessAnalysis::collectStatementIndices(StatementList& list)
{
	for (Statement* stmt : list)
	{
		size_t index = flatStatements.size();
		auto result = statementStartIndices.insert({stmt, index});
		assert(result.second); (void) result;
		flatStatements.push_back(stmt);
		
		if (auto ifElse = dyn_cast<IfElseStatement>(stmt))
		{
			collectStatementIndices(ifElse->getIfBody());
			collectStatementIndices(ifElse->getElseBody());
		}
		else if (auto loop = dyn_cast<LoopStatement>(stmt))
		{
			collectStatementIndices(loop->getLoopBody());
		}
		else if (auto exprStatement = dyn_cast<ExpressionStatement>(stmt))
		{
			Expression* expr = exprStatement->getExpression();
			if (auto assignment = dyn_cast<NAryOperatorExpression>(expr))
			{
				if (assignment->getType() == NAryOperatorExpression::Assign)
				{
					collectAssignments(stmt, assignment->operands_begin(), assignment->operands_end());
				}
			}
			
			// Expression statements represent statements that are not side-effect-free, and are all memory
			// operations, whether calls, loads or stores.
			memoryOperations.insert(index);
		}
		else if (!isa<KeywordStatement>(stmt))
		{
			llvm_unreachable("Unknown statement type!");
		}
		
		result = statementEndIndices.insert({stmt, flatStatements.size()});
		assert(result.second); (void) result;
	}
}

bool LivenessAnalysis::liveRangeContains(Expression *liveVariable, Statement *stmt)
{
	auto compareStatementMore = [&](size_t index, ExpressionUseRoot& statement)
	{
		return index > statementStartIndices.at(statement.getStatement());
	};
	
	auto compareStatementLess = [&](size_t index, ExpressionUseRoot& statement)
	{
		return index < statementStartIndices.at(statement.getStatement());
	};
	
	auto& varUsers = usingStatements.at(liveVariable);
	size_t statementIndex = statementStartIndices.at(stmt);
	
	auto previousUseDef = upper_bound(varUsers.begin(), varUsers.end(), statementIndex, compareStatementMore);
	auto nextUseDef = upper_bound(varUsers.begin(), varUsers.end(), statementIndex, compareStatementLess);
	
	// If there is at least one def before this statement, and at least one use after this statement, then
	// the live range of liveVariable contains this statement.
	// (As a shortcut, if we find a use before this statement, then necessarily there also has to be a def.)
	if (previousUseDef != varUsers.end() && nextUseDef != varUsers.end() && nextUseDef->isUse())
	{
		return true;
	}
	
	// Linearly, there is no next use/def or the next use/def is a def. Check if stmt is inside a loop and
	// see if the previous definition could reach a use at the start of the loop.
	// This is conservative with regards to break statements.
	for (auto parentLoop = getParentLoop(stmt); parentLoop != nullptr; parentLoop = getParentLoop(parentLoop))
	{
		// See if there's a use between the original statement and the end of the loop.
		auto useDefBeforeLoopEnd = lower_bound(varUsers.begin(), nextUseDef, statementEndIndices.at(parentLoop), [=](ExpressionUseRoot& statement, size_t index)
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
		auto useDefAfterLoopStart = upper_bound(varUsers.begin(), nextUseDef, statementStartIndices.at(parentLoop), compareStatementLess);
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

bool LivenessAnalysis::interferenceFree(Expression *a, Expression *b)
{
	return !any_of(usingStatements.at(b), [=](ExpressionUseRoot& useDef)
	{
		if (useDef.isDef())
		{
			Statement* statement = useDef.getStatement();
			return liveRangeContains(a, statement) && !assignmentAssigns(statement, b, a);
		}
		return false;
	});
}

void LivenessAnalysis::collectStatementIndices(FunctionNode& function)
{
	assignedExpressions.clear();
	usingStatements.clear();
	statementStartIndices.clear();
	statementEndIndices.clear();
	flatStatements.clear();
	
	collectStatementIndices(function.getBody());
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
		
		sort(statements.begin(), statements.end(), [=](ExpressionUseRoot& a, ExpressionUseRoot& b)
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
