//
// entry_points.h
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

#ifndef entry_points_h
#define entry_points_h

#include <cstddef>
#include <string>
#include <vector>

struct SymbolInfo
{
	std::string name;
	uint64_t virtualAddress;
};

class EntryPointProvider
{
public:
	virtual std::vector<uint64_t> getVisibleEntryPoints() const = 0;
	virtual const SymbolInfo* getInfo(uint64_t address) const = 0;
	
	virtual ~EntryPointProvider() = default;
};

class EntryPointRepository : public EntryPointProvider
{
	std::vector<const EntryPointProvider*> providers;
	
public:
	void addProvider(EntryPointProvider& provider);
	
	virtual std::vector<uint64_t> getVisibleEntryPoints() const override final;
	virtual const SymbolInfo* getInfo(uint64_t address) const override final;
};

#endif /* entry_points_h */
