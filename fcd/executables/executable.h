//
// executable.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is part of fcd. fcd as a whole is licensed under the terms
// of the GNU GPLv3 license, but specific parts (such as this one) are
// dual-licensed under the terms of a BSD-like license as well. You
// may use, modify and distribute this part of fcd under the terms of
// either license, at your choice. See the LICENSE file in this directory
// for details.
//

#ifndef fcd__executables_executable_h
#define fcd__executables_executable_h

#include "entry_points.h"

#include <llvm/Support/ErrorOr.h>

#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

struct StubInfo
{
	const std::string* sharedObject;
	std::string name;
};

class ExecutableFactory;

class Executable : public EntryPointProvider
{
	const uint8_t* dataBegin;
	const uint8_t* dataEnd;
	mutable std::unordered_map<uint64_t, SymbolInfo> symbols;
	mutable std::unordered_map<uint64_t, StubInfo> stubTargets;
	mutable std::set<std::string> libraries;
	
protected:
	enum StubTargetQueryResult
	{
		Unresolved,
		ResolvedInFlatNamespace,
		ResolvedInTwoLevelNamespace,
	};
	
	inline Executable(const uint8_t* begin, const uint8_t* end)
	: dataBegin(begin), dataEnd(end)
	{
	}
	
	SymbolInfo& getSymbol(uint64_t address) { return symbols[address]; }
	void eraseSymbol(uint64_t address) { symbols.erase(address); }
	
	virtual StubTargetQueryResult doGetStubTarget(uint64_t address, std::string& sharedObject, std::string& symbolName) const = 0;
	virtual std::string doGetTargetTriple() const = 0;
	
public:
	static llvm::ErrorOr<std::unique_ptr<Executable>> parse(const uint8_t* begin, const uint8_t* end);
	
	virtual std::string getExecutableType() const = 0;
	std::string getTargetTriple() const;
	
	inline const uint8_t* begin() const { return dataBegin; }
	inline const uint8_t* end() const { return dataEnd; }
	
	virtual const uint8_t* map(uint64_t address) const = 0;
	
	virtual std::vector<uint64_t> getVisibleEntryPoints() const override final;
	virtual const SymbolInfo* getInfo(uint64_t address) const override final;
	const StubInfo* getStubTarget(uint64_t address) const;
	
	virtual ~Executable() = default;
};

class ExecutableFactory
{
	std::string parameterValue;
	std::string help;
	
public:
	ExecutableFactory(std::string parameterValue, std::string help)
	: parameterValue(std::move(parameterValue)), help(std::move(help))
	{
	}
	
	const std::string& getParameterValue() const { return parameterValue; }
	const std::string& getHelp() const { return help; }
	
	virtual llvm::ErrorOr<std::unique_ptr<Executable>> parse(const uint8_t* begin, const uint8_t* end) = 0;
	virtual ~ExecutableFactory() = default;
};

#endif /* fcd__executables_executable_h */
