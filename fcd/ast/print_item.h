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

#include "dumb_allocator.h"
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
	
	// no destructor on purpose, since this type must be trivially destructible
	
	Type getType() const { return discriminant; }
	PrintableScope* getParent() { return parent; }
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const = 0;
	void dump() const;
};

class PrintableLine : public PrintableStatement
{
	NOT_NULL(const char) line;
	
public:
	static bool classof(const PrintableStatement* stmt)
	{
		return stmt->getType() == Statement;
	}
	
	PrintableLine(PrintableScope* parent, NOT_NULL(const char) line)
	: PrintableStatement(Statement, parent), line(line)
	{
	}
	
	NOT_NULL(const char) getLine() const { return line; }
	void setLine(NOT_NULL(const char) line) { this->line = line; }
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
};

class PrintableScope : public PrintableStatement
{
	DumbAllocator& allocator;
	const char* prefix;
	const char* suffix;
	PooledDeque<NOT_NULL(PrintableStatement)> prepended;
	PooledDeque<NOT_NULL(PrintableStatement)> items;
	
public:
	static bool classof(const PrintableStatement* stmt)
	{
		return stmt->getType() == Scope;
	}
	
	PrintableScope(DumbAllocator& allocator, PrintableScope* parent)
	: PrintableStatement(Scope, parent), allocator(allocator), prefix(nullptr), suffix(nullptr), prepended(allocator), items(allocator)
	{
	}
	
	const char* getPrefix() const { return prefix; }
	const char* getSuffix() const { return suffix; }
	void setPrefix(NOT_NULL(const char) prefix) { this->prefix = allocator.copyString(llvm::StringRef(prefix)); }
	void setSuffix(NOT_NULL(const char) suffix) { this->suffix = allocator.copyString(llvm::StringRef(suffix)); }
	
	PrintableStatement* prependItem(NOT_NULL(const char) line);
	PrintableStatement* appendItem(NOT_NULL(const char) line);
	PrintableStatement* appendItem(NOT_NULL(PrintableStatement) statement);
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
};

#endif /* print_item_hpp */
