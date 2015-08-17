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

struct VariableUses
{
	typedef std::list<VariableUse>::iterator iterator;
	
	Expression* expression;
	std::list<VariableUse> defs;
	std::list<VariableUse> uses;
	
	VariableUses(Expression* expr);
};

class AstVariableUses : public AstPass
{
	std::deque<Expression*> declarationOrder;
	std::unordered_map<Expression*, VariableUses> declarationUses;
	std::deque<StatementInfo> statementInfo;
	
	void visit(StatementInfo& owner, Expression** expression, bool isDef = false);
	void visit(StatementInfo* parent, Statement* statement);
	
protected:
	virtual void doRun(FunctionNode& fn) override;
	
public:
	static constexpr size_t MaxIndex = std::numeric_limits<size_t>::max();
	typedef decltype(declarationOrder)::const_iterator iterator;
	
	virtual const char* getName() const override;
	
	iterator begin() const { return declarationOrder.begin(); }
	iterator end() const { return declarationOrder.end(); }
	
	VariableUses& getUseInfo(iterator iter);
	VariableUses* getUseInfo(Expression* expr);
	
	void replaceUseWith(VariableUses::iterator iter, Expression* replacement);
	
	std::pair<VariableUses::iterator, VariableUses::iterator> usesReachedByDef(VariableUses::iterator def) const;
	std::pair<VariableUses::iterator, VariableUses::iterator> defsReachingUse(VariableUses::iterator use) const;
	
	void dump() const;
};

#endif /* ast_pass_variableuses_cpp */
