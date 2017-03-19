//
// print_item.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef print_item_hpp
#define print_item_hpp

#include "not_null.h"

#include <llvm/Support/raw_ostream.h>

#include <deque>
#include <string>

class PrintableScope;

class PrintableItem
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
	PrintableItem(Type type, PrintableScope* parent)
	: discriminant(type), parent(parent)
	{
	}
	
	Type getType() const { return discriminant; }
	PrintableScope* getParent() { return parent; }
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const = 0;
	void dump() const;
};

class PrintableLine : public PrintableItem
{
	std::string lineString;
	
public:
	static bool classof(const PrintableItem* stmt)
	{
		return stmt->getType() == Statement;
	}
	
	PrintableLine(PrintableScope* parent, std::string line)
	: PrintableItem(Statement, parent), lineString(line)
	{
	}
	
	std::string& line() { return lineString; }
	const std::string& line() const { return lineString; }
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
};

class PrintableScope : public PrintableItem
{
	std::string prefixString;
	std::string suffixString;
	std::deque<std::unique_ptr<PrintableItem>> prepended;
	std::deque<std::unique_ptr<PrintableItem>> items;
	
public:
	static bool classof(const PrintableItem* stmt)
	{
		return stmt->getType() == Scope;
	}
	
	PrintableScope(PrintableScope* parent)
	: PrintableItem(Scope, parent)
	{
	}
	
	std::string& prefix() { return prefixString; }
	const std::string& prefix() const { return prefixString; }
	std::string& suffix() { return suffixString; }
	const std::string& suffix() const { return suffixString; }
	
	PrintableItem* prependItem(std::string line);
	PrintableItem* appendItem(std::string line);
	PrintableItem* appendItem(std::unique_ptr<PrintableItem> statement);
	
	virtual void print(llvm::raw_ostream& os, unsigned indent) const override;
};

#endif /* print_item_hpp */
