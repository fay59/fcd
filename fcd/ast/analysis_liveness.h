//
// analysis_liveness.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef analysis_liveness_hpp
#define analysis_liveness_hpp

#include "expression_use.h"
#include "statements.h"

#include <llvm/ADT/PointerIntPair.h>
#include <llvm/ADT/SmallVector.h>

#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <set>

class FunctionNode;

class AssignableUseDef
{
	llvm::PointerIntPair<ExpressionUse*, 1> use;
	
public:
	AssignableUseDef(ExpressionUse* use)
	: use(use)
	{
	}
	
	ExpressionUse* get() const { return use.getPointer(); }
	Expression* getExpression() const { return get()->getUse(); }
	bool isDef() const { return use.getInt(); }
	bool isUse() const { return !isDef(); }
	void setDef() { use.setInt(1); }
};

class ExpressionUseRoot : public AssignableUseDef
{
	NOT_NULL(Statement) statement;
	
public:
	ExpressionUseRoot(AssignableUseDef useDef, NOT_NULL(Statement) statement)
	: AssignableUseDef(useDef), statement(statement)
	{
	}
	
	Statement* getStatement() { return statement; }
};

class LivenessAnalysis
{
	std::deque<Expression*> assignedExpressions;
	std::unordered_map<Expression*, llvm::SmallVector<ExpressionUseRoot, 16>> usingStatements;
	std::unordered_map<Statement*, size_t> statementStartIndices;
	std::unordered_map<Statement*, size_t> statementEndIndices;
	std::set<size_t> memoryOperations;
	std::deque<Statement*> flatStatements;
	
	// intermediate dictionary, gets cleared at some point
	std::unordered_map<Expression*, llvm::SmallVector<AssignableUseDef, 16>> usesDefs;
	
	void collectAssignments(Statement* statement, ExpressionUser::iterator iter, ExpressionUser::iterator end);
	bool assignmentAssigns(Statement* assignment, Expression* left, Expression* right);
	void collectStatementIndices(StatementList& list);
	bool liveRangeContains(Expression* liveVariable, Statement* stmt);
	bool interferenceFree(Expression* a, Expression* b);
	
public:
	static std::unordered_set<Statement*> getStatements(ExpressionUse& expressionUse);
	static std::unordered_set<Statement*> getStatements(Expression& expression);
	
	void collectStatementIndices(FunctionNode& function);
	
	const std::set<size_t>& getMemoryOperations() const
	{
		return memoryOperations;
	}
	
	Statement* getStatement(size_t index)
	{
		return flatStatements.at(index);
	}
	
	std::pair<size_t, size_t> getIndex(Statement* statement) const
	{
		return std::make_pair(statementStartIndices.at(statement), statementEndIndices.at(statement));
	}
	
	std::deque<Expression*> getAssignedExpressions() const
	{
		return assignedExpressions;
	}
	
	const auto& getUsesDefs(Expression& expression) const
	{
		return usingStatements.at(&expression);
	}
	
	bool congruent(Expression* a, Expression* b)
	{
		return interferenceFree(a, b) && interferenceFree(b, a);
	}
};

#endif /* analysis_liveness_hpp */
