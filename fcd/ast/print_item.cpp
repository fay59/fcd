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
	tabulate(os, indent) << lineString << '\n';
}

PrintableItem* PrintableScope::prependItem(string line)
{
	prepended.emplace_back(llvm::make_unique<PrintableLine>(this, move(line)));
	return prepended.back().get();
}

PrintableItem* PrintableScope::appendItem(string line)
{
	return appendItem(llvm::make_unique<PrintableLine>(this, move(line)));
}

PrintableItem* PrintableScope::appendItem(unique_ptr<PrintableItem> statement)
{
	items.emplace_back(move(statement));
	return items.back().get();
}

void PrintableScope::print(raw_ostream &os, unsigned int indent) const
{
	if (!prefixString.empty())
	{
		tabulate(os, indent) << prefixString << '\n';
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
	if (!suffixString.empty())
	{
		tabulate(os, indent) << suffixString << '\n';
	}
}
