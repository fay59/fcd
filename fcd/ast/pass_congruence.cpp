//
// pass_congruence.cpp
// Copyright (C) 2017 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "analysis_liveness.h"
#include "ast_passes.h"
#include "visitor.h"

#include <llvm/ADT/SmallVector.h>

#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace llvm;
using namespace std;

namespace
{
	struct HashSymmetricPair : private hash<Expression*>
	{
		size_t operator()(const pair<Expression*, Expression*>& that) const
		{
			const auto& hashBase = *static_cast<const hash<Expression*>*>(this);
			return hashBase(that.first) ^ hashBase(that.second);
		}
	};
	
	bool isExpressionAddressable(NOT_NULL(Expression) expr)
	{
		if (auto assignable = dyn_cast<AssignableExpression>(expr))
		{
			return assignable->addressable;
		}
		return true;
	}
}

namespace
{
	void mergeVariables(AstContext& ctx, Expression* toReplace, Expression* replaceWith)
	{
		assert(toReplace != replaceWith);
		while (!toReplace->uses_empty())
		{
			auto& use = *toReplace->uses_begin();
			use.setUse(replaceWith);
			
			if (auto assignment = dyn_cast<NAryOperatorExpression>(use.getUser()))
			if (assignment->getType() == NAryOperatorExpression::Assign)
			if (all_of(assignment->operands(), [=](Expression* expr) { return expr == replaceWith; }))
			{
				// This assignment is now useless, drop it everywhere. (There is most likely just one use of it.)
				while (assignment->uses_size() > 0)
				{
					auto statement = cast<ExpressionStatement>(assignment->uses_begin()->getUser());
					StatementList::erase(statement);
					statement->dropAllReferences();
				}
			}
		}
	}
}

void AstMergeCongruentVariables::doRun(FunctionNode &fn)
{
	LivenessAnalysis liveness;
	liveness.collectStatementIndices(fn);
	
	// Can we remove explicit load and call expression statements?
	// Loads and calls are special in that they are themselves rooted as statements. For instance, a load expression for
	// `foo` has a `foo;` statement, which typically gets rewritten as `int anon1 = foo;` by the printer, and subsequent
	// users show "anon1" instead of foo. This step is necessary to ensure the memory operation order. For instance,
	// with a function "bar()" that modifies foo, "int anon1 = foo; bar()" is not the same as `bar(); int anon1 = foo;`.
	// However, in many cases, there are no memory operations between the rooting statement and the expression's uses,
	// so we wouldn't need that rooting statement. This is what this code checks and tries to simplify.
	auto& memoryOperations = liveness.getMemoryOperations();
	for (auto memoryOperationStatement : memoryOperations)
	{
		Expression* expr = cast<ExpressionStatement>(liveness.getStatement(memoryOperationStatement))->getExpression();
		
		// Exclude operator expressions, since the only use case of a rooted operator expression is to assign a value,
		// and assignments are never used so we don't gain anything from attempting to transform them. Also exclude
		// calls that are never used, because otherwise they'll just be removed.
		if (isa<NAryOperatorExpression>(expr) || (isa<CallExpression>(expr) && expr->uses_size() == 1))
		{
			continue;
		}
		
		Statement* declaration = nullptr;
		Statement* firstUse = nullptr;
		size_t declarationLocation = numeric_limits<size_t>::max();
		size_t firstUseLocation = numeric_limits<size_t>::max();
		for (Statement* statement : getUsingStatements(*expr))
		{
			// Kind of a heuristic. It works in loops because call results have to be assigned to a ɸ node and
			// therefore it's not sequentially used before it's called.
			auto indexPair = liveness.getIndex(statement);
			size_t index = indexPair.first;
			if (auto doWhile = dyn_cast<LoopStatement>(statement))
			if (doWhile->getPosition() == LoopStatement::PostTested)
			{
				index = indexPair.second;
			}
			
			if (index < declarationLocation)
			{
				firstUse = declaration;
				firstUseLocation = declarationLocation;
				declaration = statement;
				declarationLocation = index;
			}
			else if (index < firstUseLocation)
			{
				firstUse = statement;
				firstUseLocation = index;
			}
		}
		
		// Even if the expression has multiple uses, we can count on them being collapsed into a temporary before the
		// first use, so we only need to consider whether memory operations happen between the definition and the first
		// use.
		auto iter = memoryOperations.upper_bound(memoryOperationStatement);
		if (iter == memoryOperations.end() || *iter >= firstUseLocation)
		{
			assert(cast<ExpressionStatement>(declaration)->getExpression() == expr);
			// However, the transformation is only valid if the definition and the use have the same reaching condition:
			// for instance, in `a = foo(); if (bar) puts(a);` is not the same as `if (bar) puts(foo())`, since in the
			// first case `foo()` is called unconditionally.
			if (declaration->getParentList() == firstUse->getParentList())
			{
				StatementList::erase(declaration);
				declaration->dropAllReferences();
			}
		}
	}
	
	unordered_set<pair<Expression*, Expression*>, HashSymmetricPair> candidateSet;
	auto assignableExpressions = liveness.getAssignedExpressions();
	for (Expression* key : assignableExpressions)
	{
		for (const AssignableUseDef& useDef : liveness.getUsesDefs(*key))
		{
			if (useDef.isUse())
			{
				continue;
			}
			
			auto user = useDef.get()->getUser();
			assert(cast<NAryOperatorExpression>(user)->getType() == NAryOperatorExpression::Assign);
			for (Expression* assignmentOperand : user->operands())
			{
				if (assignmentOperand != key && find(assignableExpressions, assignmentOperand) != assignableExpressions.end())
				{
					candidateSet.emplace(key, assignmentOperand);
				}
			}
		}
	}
	
	// Only merge after we're officially done touching the liveness analysis object, since it holds a ton of references.
	deque<pair<ExpressionReference, ExpressionReference>> mergeList;
	for (auto& candidate : candidateSet)
	{
		if (liveness.congruent(candidate.first, candidate.second))
		{
			if (!isExpressionAddressable(candidate.first))
			{
				mergeList.emplace_back(candidate.first, candidate.second);
			}
			else if (!isExpressionAddressable(candidate.second))
			{
				mergeList.emplace_back(candidate.second, candidate.first);
			}
		}
	}
	
	for (auto& merge : mergeList)
	{
		// Since CongruenceCandidate contains ExpressionReferences, pointers in the list are replaced by the
		// replaceAllUsesWith-equivalent code of mergeVariables. This means that we can end up with a candidate whose
		// left and right are already the same variables.
		if (merge.first.get() == merge.second.get())
		{
			continue;
		}
		
		mergeVariables(context(), merge.first.get(), merge.second.get());
	}
}

const char* AstMergeCongruentVariables::getName() const
{
	return "Merge Congruent Variables";
}
