//
// print_item.h
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

#ifndef print_item_hpp
#define print_item_hpp

#include "llvm_warnings.h"
#include "not_null.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <string>
#include <vector>

class PrintableScope;

class PrintableStatement
{
public:
	enum Type
	{
		Scope,
		Statement,
	};
	
private:
	Type discriminant;
	PrintableScope* parent;
	
public:
	PrintableStatement(Type type, PrintableScope* parent)
	: discriminant(type), parent(parent)
	{
	}
	
	virtual ~PrintableStatement() = default;
	
	Type getType() const { return discriminant; }
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const = 0;
	void dump() const;
};

union PrintableItem;

class PrintableExpression : public PrintableStatement
{
	NOT_NULL(const char) line;
	
public:
	PrintableExpression(PrintableScope* parent, NOT_NULL(const char) line)
	: PrintableStatement(Statement, parent), line(line)
	{
	}
	
	NOT_NULL(const char) getLine() const { return line; }
	void setLine(NOT_NULL(const char) line) { this->line = line; }
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
};

class PrintableScope : public PrintableStatement
{
	const char* prefix;
	const char* suffix;
	std::vector<PrintableItem> items;
	
public:
	PrintableScope(PrintableScope* parent);
	~PrintableScope() noexcept;
	
	const char* getPrefix() const { return prefix; }
	const char* getSuffix() const { return suffix; }
	void setPrefix(NOT_NULL(const char) prefix) { this->prefix = prefix; }
	void setSuffix(NOT_NULL(const char) suffix) { this->suffix = suffix; }
	
	template<typename... T>
	void prependItem(T&&... args)
	{
		items.emplace(items.begin(), std::forward(args)...);
	}
	
	template<typename... T>
	void appendItem(T&&... args)
	{
		items.emplace_back(std::forward(args)...);
	}
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
};

union PrintableItem
{
	PrintableScope scope;
	PrintableExpression expression;
	
	PrintableItem(PrintableScope* parent)
	: scope(parent)
	{
	}
	
	PrintableItem(PrintableScope* parent, NOT_NULL(const char) line)
	: expression(parent, line)
	{
	}
	
	~PrintableItem() noexcept;
	
	PrintableStatement& statement() { return scope; }
	const PrintableStatement& statement() const { return scope; }
};

#endif /* print_item_hpp */
