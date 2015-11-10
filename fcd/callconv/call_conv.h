//
// call_conv.h
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

#ifndef call_conv_hpp
#define call_conv_hpp

#include "executable.h"
#include "llvm_warnings.h"
#include "params_registry.h"
#include "pass_targetinfo.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Function.h>
SILENCE_LLVM_WARNINGS_END()

#include <cassert>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

// CallingConvention objects can identify parameters in a function following their own rules.
class CallingConvention
{
public:
	static bool registerCallingConvention(CallingConvention* cc);
	static CallingConvention* getCallingConvention(const std::string& name);
	static CallingConvention* getMatchingCallingConvention(TargetInfo& target, Executable& executable);
	static std::vector<CallingConvention*> getCallingConventions();
	
	virtual const char* getName() const = 0;
	virtual const char* getHelp() const;
	virtual bool matches(TargetInfo& target, Executable& executable) const;
	
	virtual void getAnalysisUsage(llvm::AnalysisUsage& au) const;
	
	// used for functions with a body
	virtual bool analyzeFunction(ParameterRegistry& registry, CallInformation& fillOut, llvm::Function& func) = 0;
	
	// used for functions without a body
	virtual bool analyzeFunctionType(ParameterRegistry& registry, CallInformation& fillOut, llvm::FunctionType& type);
	
	// used for indirect calls and vararg calls
	virtual bool analyzeCallSite(ParameterRegistry& registry, CallInformation& fillOut, llvm::CallSite cs);
	
	virtual ~CallingConvention() = default;
};

template<class CC>
class RegisterCallingConvention
{
	CC callingConvention;
	
public:
	template<typename... TArgs>
	RegisterCallingConvention(TArgs&&... args)
	: callingConvention(std::forward(args)...)
	{
		bool registered = CallingConvention::registerCallingConvention(&callingConvention);
		assert(registered);
	}
};

#endif /* call_conv_hpp */
