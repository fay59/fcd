//
// anyarch_lib.cpp
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

#include "anyarch_lib.h"
#include "cc_common.h"

#include <string>
#include <unordered_map>

using namespace llvm;
using namespace std;

// TODO: some day, use the Clang API to parse headers.

namespace
{
	template<typename T, size_t N>
	constexpr size_t countof(T (&)[N])
	{
		return N;
	}
	
	struct ParameterInfo
	{
		size_t count;
		bool returns;
		bool variadic;
	};
	
	static unordered_map<string, ParameterInfo> knownFunctions
	{
		{"__assert_fail",		{4, false, false}},
		{"__libc_start_main",	{7, true, false}},
		{"__gmon_start__",		{0, false, false}},
		{"_IO_getc",			{1, true, false}},
		{"_IO_putc",			{2, true, false}},
		{"atoi",				{1, true, false}},
		{"exit",				{1, false, false}},
		{"calloc",				{2, true, false}},
		{"difftime",			{2, true, false}},
		{"fclose",				{1, true, false}},
		{"fgets",				{3, true, false}},
		{"fflush",				{1, true, false}},
		{"fopen",				{2, true, false}},
		{"fork",				{0, true, false}},
		{"free",				{1, false, false}},
		{"fscanf",				{2, true, true}},
		{"fseek",				{3, true, false}},
		{"ftell",				{1, true, false}},
		{"fwrite",				{4, true, false}},
		{"getchar",				{0, true, false}},
		{"getenv",				{1, true, false}},
		{"gets",				{1, true, false}},
		{"isalpha",				{1, true, false}},
		{"localtime",			{1, true, false}},
		{"malloc",				{1, true, false}},
		{"memset",				{3, true, false}},
		{"putchar",				{1, true, false}},
		{"puts",				{1, true, false}},
		{"printf",              {1, true, true}},
		{"rand",				{0, true, false}},
		{"random",				{0, true, false}},
		{"scanf",				{1, true, true}},
		{"setbuf",				{2, false, false}},
		{"sprintf",				{2, true, true}},
		{"srand",				{1, false, false}},
		{"sscanf",				{2, true, true}},
		{"strcasecmp",			{2, true, false}},
		{"strchr",				{2, true, false}},
		{"strcpy",				{2, true, false}},
		{"strlen",				{1, true, false}},
		{"strtol",				{3, true, false}},
		{"system",				{1, true, false}},
		{"time",				{1, true, false}},
		{"toupper",				{1, true, false}},
		{"wait",				{1, true, false}},
		
		// this list is getting long...
		{"_ZNSsC1ERKSs",		{2, false, false}},	// string::string(const string&)
		{"_ZNKSs6lengthEv",		{1, true, false}},	// string::length()
		{"_ZNSsD1Ev",			{1, false, false}}, // string::~string()
	};
}

const char* CallingConvention_AnyArch_Library::getName() const
{
	return "Any/Interactive";
}

bool CallingConvention_AnyArch_Library::matches(TargetInfo &target, Executable &executable) const
{
	// Match nothing.
	return false;
}

bool CallingConvention_AnyArch_Library::analyzeFunction(ParameterRegistry &registry, CallInformation &fillOut, llvm::Function &function)
{
	if (auto node = function.getMetadata("fcd.importname"))
	if (auto nameNode = dyn_cast<MDString>(node->getOperand(0)))
	{
		auto name = nameNode->getString();
		auto iter = knownFunctions.find(name.str());
		if (iter != knownFunctions.end())
		{
			const auto& protoInfo = iter->second;
			return hackhack_fillFromParamInfo(function.getContext(), registry, fillOut, protoInfo.returns, protoInfo.count, protoInfo.variadic);
		}
	}
	return false;
}
