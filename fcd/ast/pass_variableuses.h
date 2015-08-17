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

#ifndef ast_pass_variableuses_cpp
#define ast_pass_variableuses_cpp

#include "nodes.h"
#include "pass.h"

#include <deque>
#include <limits>
#include <list>
#include <map>
#include <unordered_map>

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
	NOT_NULL(Expression) definitionValue;
	
	inline VariableDef(StatementInfo& owner, Expression* defined, Expression* value)
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

class AstVariableUses : public AstPass
{
	std::deque<Expression*> declarationOrder;
	std::unordered_map<Expression*, VariableReferences> declarationUses;
	std::deque<StatementInfo> statementInfo;
	
	void visitSubexpression(StatementInfo& owner, Expression* subexpression);
	void visitUse(StatementInfo& owner, Expression** location);
	void visitDef(StatementInfo& owner, Expression* definedValue, Expression* value);
	void visit(StatementInfo* parent, Statement* statement);
	
protected:
	virtual void doRun(FunctionNode& fn) override;
	
public:
	static constexpr size_t MaxIndex = std::numeric_limits<size_t>::max();
	typedef decltype(declarationOrder)::const_iterator iterator;
	
	virtual const char* getName() const override;
	
	iterator begin() const { return declarationOrder.begin(); }
	iterator end() const { return declarationOrder.end(); }
	
	VariableReferences& getUseInfo(iterator iter);
	VariableReferences* getUseInfo(Expression* expr);
	
	void replaceUseWith(VariableReferences::use_iterator iter, Expression* replacement);
	
	void dump() const;
};

#endif /* ast_pass_variableuses_cpp */
