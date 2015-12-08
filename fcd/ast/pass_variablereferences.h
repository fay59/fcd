//
// pass_variableuses.h
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

#ifndef fcd__ast_pass_variablereferences_h
#define fcd__ast_pass_variablereferences_h

#include "statements.h"
#include "pass.h"

#include <deque>
#include <limits>
#include <list>
#include <set>
#include <unordered_map>
#include <unordered_set>

struct StatementInfo
{
	StatementInfo* parent;
	Statement* statement;
	size_t indexBegin;
	size_t indexEnd;
	
	inline StatementInfo(Statement* stmt, size_t indexBegin, StatementInfo* parent = nullptr)
	: parent(parent), statement(stmt), indexBegin(indexBegin), indexEnd(indexBegin)
	{
	}
};

struct VariableUse
{
	StatementInfo& owner;
	NOT_NULL(Expression*) location;
	
	inline VariableUse(StatementInfo& owner, Expression** location)
	: owner(owner), location(location)
	{
	}
};

struct VariableDef
{
	StatementInfo& owner;
	NOT_NULL(Expression) definedExpression;
	NOT_NULL(Expression*) definitionValue;
	
	inline VariableDef(StatementInfo& owner, Expression* defined, Expression** value)
	: owner(owner), definedExpression(defined), definitionValue(value)
	{
	}
};

struct VariableReferences
{
	typedef std::list<VariableUse>::iterator use_iterator;
	typedef std::list<VariableDef>::iterator def_iterator;
	
	Expression* expression;
	std::list<VariableDef> defs;
	std::list<VariableUse> uses;
	
	VariableReferences(Expression* expr);
};

enum class ReachStrength
{
	NotReaching,
	Reaching,
	Dominating,
};

typedef std::pair<VariableReferences::use_iterator, ReachStrength> ReachedUse;

class AstVariableReferences
{
	std::deque<Expression*> declarationOrder;
	std::deque<StatementInfo> statementInfo;
	std::unordered_map<Expression*, VariableReferences> references;
	std::unordered_map<Expression*, std::set<size_t>> dominatingDefs;
	
	void visitSubexpression(std::unordered_set<Expression*>& setExpressions, StatementInfo& owner, Expression* subexpression);
	void visitUse(std::unordered_set<Expression*>& setExpressions, StatementInfo& owner, Expression** location);
	void visitDef(std::unordered_set<Expression*>& setExpressions, StatementInfo& owner, Expression* definedValue, Expression** value);
	void visit(std::unordered_set<Expression*>& setExpressions, StatementInfo* parent, Statement* statement);
	
public:
	static constexpr size_t MaxIndex = std::numeric_limits<size_t>::max();
	typedef decltype(declarationOrder)::const_iterator iterator;
	typedef decltype(declarationOrder)::const_reverse_iterator reverse_iterator;
	
	void construct(FunctionNode& fn);
	
	iterator begin() const { return declarationOrder.begin(); }
	iterator end() const { return declarationOrder.end(); }
	
	reverse_iterator rbegin() const { return declarationOrder.rbegin(); }
	reverse_iterator rend() const { return declarationOrder.rend(); }
	
	VariableReferences& getReferences(iterator iter);
	VariableReferences& getReferences(reverse_iterator iter);
	VariableReferences* getReferences(Expression* expr);
	
	llvm::SmallVector<VariableReferences*, 4> referencesInExpression(Expression* expr);
	llvm::SmallVector<ReachedUse, 4> usesReachedByDef(VariableReferences::def_iterator iter);
	void replaceUseWith(DumbAllocator& pool, VariableReferences::use_iterator iter, Expression* replacement);
	VariableReferences::def_iterator removeDef(VariableReferences::def_iterator iter);
	
	void dump() const;
};

class AstVariableReferencesPass : public AstModulePass
{
	std::unordered_map<FunctionNode*, AstVariableReferences> variableReferences;
	
protected:
	virtual void doRun(std::deque<std::unique_ptr<FunctionNode>>& functions) override;
	
public:
	virtual const char* getName() const override;
	
	AstVariableReferences* getReferences(FunctionNode& fn);
};

#endif /* fcd__ast_pass_variablereferences_h */
