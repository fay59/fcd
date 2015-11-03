//
// anyarch_anycc.h
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

#ifndef anyarch_anycc_h
#define anyarch_anycc_h

#include "call_conv.h"
#include "params_registry.h"

#include <string>

class CallingConvention_AnyArch_AnyCC : public CallingConvention
{
public:
	static const char* name;
	
	virtual const char* getName() const override;
	virtual bool matches(TargetInfo& target, Executable& executable) const override;
	virtual void getAnalysisUsage(llvm::AnalysisUsage& au) const override;
	virtual bool analyzeFunction(ParameterRegistry& registry, CallInformation& fillOut, llvm::Function& func) override;
};

#endif /* anyarch_anycc_hpp */
