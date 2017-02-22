//
// print_item.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "print_item.h"

using namespace llvm;
using namespace std;

namespace
{
	raw_ostream& tabulate(raw_ostream& os, unsigned count)
	{
		static const char tabs[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";
		constexpr size_t tabCount = sizeof tabs - 1;
		while (count > tabCount)
		{
			os << tabs;
			count -= tabCount;
		}
		os.write(tabs, count);
		return os;
	}
}

void PrintableItem::dump() const
{
	print(errs(), 0);
}

void PrintableLine::print(raw_ostream &os, unsigned int indent) const
{
	tabulate(os, indent) << line << '\n';
}

PrintableItem* PrintableScope::prependItem(NOT_NULL(const char) line)
{
	auto expr = pool().allocate<PrintableLine>(pool(), this, line);
	prepended.push_back(expr);
	return expr;
}

PrintableItem* PrintableScope::appendItem(NOT_NULL(const char) line)
{
	auto expr = pool().allocate<PrintableLine>(pool(), this, line);
	return appendItem(expr);
}

PrintableItem* PrintableScope::appendItem(NOT_NULL(PrintableItem) statement)
{
	items.push_back(statement);
	return statement;
}

void PrintableScope::print(raw_ostream &os, unsigned int indent) const
{
	if (prefix != nullptr)
	{
		tabulate(os, indent) << prefix << '\n';
	}
	tabulate(os, indent) << "{\n";
	
	for (const auto& item : prepended)
	{
		item->print(os, indent + 1);
	}
	
	for (const auto& item : items)
	{
		item->print(os, indent + 1);
	}
	
	tabulate(os, indent) << "}\n";
	if (suffix != nullptr)
	{
		tabulate(os, indent) << suffix << '\n';
	}
}
