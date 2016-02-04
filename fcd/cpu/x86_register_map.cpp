//
// x86_register_map.cpp
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

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <algorithm>
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
		
		inline void regInfo(size_t size, const string& name)
		{
			TargetRegisterInfo result = { offset, size, {0, fieldOffset, 0}, name };
			info.push_back(result);
		}
		
		inline void regInfo(size_t size, size_t offset, const string& name)
		{
			TargetRegisterInfo result = { offset, size, {0, fieldOffset, 0}, name };
			info.push_back(result);
		}
		
		void singleLetterReg(const string& name)
		{
			string extended = name + "x";
			regInfo(8, "r" + extended);
			regInfo(4, "e" + extended);
			regInfo(2, extended);
			regInfo(1, name + "l");
			regInfo(1, offset + 1, name + "h");
			offset += 8;
			fieldOffset++;
		}
		
		void twoLetterReg(const string& name)
		{
			regInfo(8, "r" + name);
			regInfo(4, "e" + name);
			regInfo(2, name);
			regInfo(1, name + "l");
			offset += 8;
			fieldOffset++;
		}
		
		void extendedReg(unsigned num)
		{
			string name;
			raw_string_ostream(name) << 'r' << num;
			regInfo(8, name);
			regInfo(4, name + "d");
			regInfo(2, name + "w");
			regInfo(1, name + "b");
			offset += 8;
			fieldOffset++;
		}
		
		void segmentReg(const string& name)
		{
			regInfo(8, name);
			offset += 8;
			fieldOffset++;
		}
	};
	
	std::vector<TargetRegisterInfo> x86RegisterInfo = []()
	{
		RegInfoBuilder builder;
		builder.singleLetterReg("z");
		builder.singleLetterReg("a");
		builder.singleLetterReg("b");
		builder.singleLetterReg("c");
		builder.singleLetterReg("d");
		builder.twoLetterReg("si");
		builder.twoLetterReg("di");
		builder.twoLetterReg("bp");
		builder.twoLetterReg("sp");
		builder.twoLetterReg("ip");
		for (unsigned i = 8; i < 16; i++)
		{
			builder.extendedReg(i);
		}
		builder.segmentReg("cs");
		builder.segmentReg("ds");
		builder.segmentReg("es");
		builder.segmentReg("fs");
		builder.segmentReg("gs");
		builder.segmentReg("ss");
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
