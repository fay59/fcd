//
// entry_points.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
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
