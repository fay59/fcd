//
// pass_lib_reguse.cpp
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

#include "passes.h"

#include <string>
#include <unordered_map>

using namespace llvm;
using namespace std;

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
	
	struct LibraryRegisterUse : public ModulePass
	{
		static char ID;
		
		LibraryRegisterUse() : ModulePass(ID)
		{
		}
		
		virtual void getAnalysisUsage(AnalysisUsage &au) const override
		{
			au.addRequired<TargetInfo>();
			au.addRequired<RegisterUseWrapper>();
			ModulePass::getAnalysisUsage(au);
		}
		
		virtual const char* getPassName() const override
		{
			return "Library Register Use";
		}
		
		virtual bool runOnModule(Module& m) override
		{
			bool changed = false;
			TargetInfo& targetInfo = getAnalysis<TargetInfo>();
			auto& regUse = getAnalysis<RegisterUseWrapper>();
			
			for (Function& function : m.getFunctionList())
			{
				if (auto node = function.getMetadata("fcd.importname"))
				if (auto nameNode = dyn_cast<MDString>(node->getOperand(0)))
				{
					auto name = nameNode->getString();
					if (name != function.getName())
					{
						function.setName(name);
						changed = true;
					}
					
					auto iter = knownFunctions.find(name.str());
					if (iter != knownFunctions.end())
					{
						hackhack_systemVabi(targetInfo, regUse.getOrCreateModRefInfo(&function), iter->second);
						function.deleteBody();
						changed = true;
					}
				}
			}
			
			return changed;
		}
		
		// This needs to be updated to support multiple front-ends
		void hackhack_systemVabi(const TargetInfo& x86Info, RegisterUse::mapped_type& table, ParameterInfo& info)
		{
			static const char* const argumentRegs[] = {
				"rdi", "rsi", "rdx", "rcx", "r8", "r9"
			};
			
			table[x86Info.registerNamed("rax")] = info.returns ? AliasAnalysis::Mod : AliasAnalysis::NoModRef;
			table[x86Info.registerNamed("rbx")] = AliasAnalysis::NoModRef;
			
			table[x86Info.registerNamed("r10")] = AliasAnalysis::NoModRef;
			table[x86Info.registerNamed("r11")] = AliasAnalysis::NoModRef;
			table[x86Info.registerNamed("r12")] = AliasAnalysis::NoModRef;
			table[x86Info.registerNamed("r13")] = AliasAnalysis::NoModRef;
			table[x86Info.registerNamed("r14")] = AliasAnalysis::NoModRef;
			table[x86Info.registerNamed("r15")] = AliasAnalysis::NoModRef;
			
			table[x86Info.registerNamed("rbp")] = AliasAnalysis::NoModRef;
			table[x86Info.registerNamed("rsp")] = info.variadic ? AliasAnalysis::Ref : AliasAnalysis::NoModRef;
			table[x86Info.registerNamed("rip")] = AliasAnalysis::NoModRef;
			
			for (size_t i = 0; i < countof(argumentRegs); i++)
			{
				const TargetRegisterInfo* uniqued = x86Info.registerNamed(argumentRegs[i]);
				table[uniqued] = i < info.count ? AliasAnalysis::Ref : AliasAnalysis::NoModRef;
			}
		}
	};
	
	char LibraryRegisterUse::ID = 0;
}

ModulePass* createLibraryRegisterUsePass()
{
	return new LibraryRegisterUse;
}

INITIALIZE_PASS_BEGIN(LibraryRegisterUse, "libreguse", "External library information about register use", false, true)
INITIALIZE_PASS_DEPENDENCY(TargetInfo)
INITIALIZE_PASS_DEPENDENCY(RegisterUseWrapper)
INITIALIZE_PASS_END(LibraryRegisterUse, "libreguse", "External library information about register use", false, true)
