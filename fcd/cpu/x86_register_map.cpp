//
// x86_register_map.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//


#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

#include "x86_regs.h"
#include "x86_register_map.h"

using namespace llvm;
using namespace std;

namespace
{
	struct RegInfoBuilder
	{
		vector<TargetRegisterInfo> info;
		size_t offset = 0;
		unsigned fieldOffset = 0;
		
		inline void regInfo(size_t size, const string& name, x86_reg registerId)
		{
			if (registerId != X86_REG_INVALID)
			{
				TargetRegisterInfo result = { offset, 0, size, {fieldOffset, 0}, name, registerId };
				info.push_back(result);
			}
		}
		
		inline void regInfo(size_t size, size_t off, const string& name, x86_reg registerId)
		{
			if (registerId != X86_REG_INVALID)
			{
				TargetRegisterInfo result = { off, off - this->offset, size, {fieldOffset, 0}, name, registerId };
				info.push_back(result);
			}
		}
		
		void singleLetterReg(char letter, x86_reg r64, x86_reg r32, x86_reg r16, x86_reg r8h, x86_reg r8l)
		{
			string name(1, letter);
			string extended = name + "x";
			regInfo(8, "r" + extended, r64);
			regInfo(4, "e" + extended, r32);
			regInfo(2, extended, r16);
			regInfo(1, name + "l", r8l);
			regInfo(1, offset + 1, name + "h", r8h);
			offset += 8;
			fieldOffset++;
		}
		
		void twoLetterReg(char letter1, char letter2, x86_reg r64, x86_reg r32, x86_reg r16, x86_reg r8)
		{
			string name;
			name.push_back(letter1);
			name.push_back(letter2);
			
			regInfo(8, "r" + name, r64);
			regInfo(4, "e" + name, r32);
			regInfo(2, name, r16);
			regInfo(1, name + "l", r8);
			offset += 8;
			fieldOffset++;
		}
		
		void extendedReg(unsigned num, x86_reg r64, x86_reg r32, x86_reg r16, x86_reg r8)
		{
			string name;
			raw_string_ostream(name) << 'r' << num;
			regInfo(8, name, r64);
			regInfo(4, name + "d", r32);
			regInfo(2, name + "w", r16);
			regInfo(1, name + "b", r8);
			offset += 8;
			fieldOffset++;
		}
		
		void segmentReg(const string& name, x86_reg id)
		{
			regInfo(8, name, id);
			offset += 8;
			fieldOffset++;
		}
	};
	
#define ONE_LETTER_REG(letter) \
	builder.singleLetterReg((char)tolower((#letter)[0]), \
		X86_REG_R##letter##X, \
		X86_REG_E##letter##X, \
		X86_REG_##letter##X, \
		X86_REG_##letter##H, \
		X86_REG_##letter##L)
	
#define TWO_LETTER_REG(letters) \
	builder.twoLetterReg((char)tolower((#letters)[0]), (char)tolower((#letters)[1]), \
		X86_REG_R##letters, \
		X86_REG_E##letters, \
		X86_REG_##letters, \
		X86_REG_##letters##L)
	
#define EXTENDED_REG(num) \
	builder.extendedReg((num), \
		X86_REG_R##num, X86_REG_R##num##D, X86_REG_R##num##W, X86_REG_R##num##B)
	
	std::vector<TargetRegisterInfo> x86RegisterInfo = []()
	{
		RegInfoBuilder builder;
		builder.singleLetterReg('z', X86_REG_RIZ, X86_REG_EIZ, X86_REG_INVALID, X86_REG_INVALID, X86_REG_INVALID);
		ONE_LETTER_REG(A);
		ONE_LETTER_REG(B);
		ONE_LETTER_REG(C);
		ONE_LETTER_REG(D);
		TWO_LETTER_REG(SI);
		TWO_LETTER_REG(DI);
		TWO_LETTER_REG(BP);
		TWO_LETTER_REG(SP);
		builder.twoLetterReg('i', 'p', X86_REG_RIP, X86_REG_EIP, X86_REG_IP, X86_REG_INVALID);
		
		EXTENDED_REG(8);
		EXTENDED_REG(9);
		EXTENDED_REG(10);
		EXTENDED_REG(11);
		EXTENDED_REG(12);
		EXTENDED_REG(13);
		EXTENDED_REG(14);
		EXTENDED_REG(15);
		
		builder.segmentReg("cs", X86_REG_CS);
		builder.segmentReg("ds", X86_REG_DS);
		builder.segmentReg("es", X86_REG_ES);
		builder.segmentReg("fs", X86_REG_FS);
		builder.segmentReg("gs", X86_REG_GS);
		builder.segmentReg("ss", X86_REG_SS);
		return builder.info;
	}();
}

void x86TargetInfo(TargetInfo* info)
{
	info->targetName() = "x86_64";
	info->setTargetRegisterInfo(x86RegisterInfo);
	
	auto rsp_iter = find_if(x86RegisterInfo.begin(), x86RegisterInfo.end(), [](const TargetRegisterInfo& info)
	{
		return info.name == "rsp";
	});
	
	info->setStackPointer(*rsp_iter);
}
