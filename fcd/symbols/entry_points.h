//
// entry_points.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
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

class EntryPointRepository final : public EntryPointProvider
{
	std::vector<const EntryPointProvider*> providers;
	
public:
	void addProvider(EntryPointProvider& provider);
	
	std::vector<uint64_t> getVisibleEntryPoints() const override;
	const SymbolInfo* getInfo(uint64_t address) const override;
};

#endif /* entry_points_h */
