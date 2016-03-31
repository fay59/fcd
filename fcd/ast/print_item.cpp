//
// print_item.cpp
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

void PrintableStatement::dump() const
{
	print(errs(), 0);
}

void PrintableLine::print(raw_ostream &os, unsigned int indent) const
{
	tabulate(os, indent) << line << '\n';
}

void PrintableScope::declare(NotNull<const char> type, NotNull<const char> name)
{
	size_t typeSize = strlen(type);
	size_t nameSize = strlen(name);
	char* string = allocator.allocateDynamic<char>(typeSize + nameSize + 3); // ' ', ';', '\0'
	strcpy(string, type);
	strcpy(&string[typeSize + 1], name);
	string[typeSize] = ' ';
	string[typeSize + nameSize + 1] = ';';
	string[typeSize + nameSize + 2] = '\0';
	
	auto expr = allocator.allocate<PrintableLine>(this, string);
	declarations.push_back(expr);
}

void PrintableScope::appendItem(NotNull<const char> line)
{
	auto expr = allocator.allocate<PrintableLine>(this, line);
	items.push_back(expr);
}

void PrintableScope::print(raw_ostream &os, unsigned int indent) const
{
	if (prefix != nullptr)
	{
		tabulate(os, indent) << prefix << '\n';
	}
	tabulate(os, indent) << "{\n";
	
	for (const auto& item : declarations)
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
