//
// entry_points.cpp
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

#include "command_line.h"
#include "entry_points.h"

#include <unordered_set>

using namespace llvm;
using namespace std;

void EntryPointRepository::addProvider(EntryPointProvider &provider)
{
	providers.push_back(&provider);
}

vector<uint64_t> EntryPointRepository::getVisibleEntryPoints() const
{
	unordered_set<uint64_t> entryPoints;
	for (auto provider : providers)
	{
		auto entryPointList = provider->getVisibleEntryPoints();
		entryPoints.insert(entryPointList.begin(), entryPointList.end());
	}
	return vector<uint64_t>(entryPoints.begin(), entryPoints.end());
}

const SymbolInfo* EntryPointRepository::getInfo(uint64_t address) const
{
	for (auto iter = providers.rbegin(); iter != providers.rend(); ++iter)
	{
		if (auto info = (*iter)->getInfo(address))
		{
			return info;
		}
	}
	return nullptr;
}
