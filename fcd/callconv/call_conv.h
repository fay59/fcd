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
#include "pass_reguse.h"
#include "pass_targetinfo.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Function.h>
SILENCE_LLVM_WARNINGS_END()

#include <cassert>
#include <memory>
#include <set>
#include <string>
#include <utility>

class CallingConvention;

class ParameterIdentificationPass : public llvm::FunctionPass
{
	friend class CallingConvention;
	
	CallingConvention* cc;
	ParameterRegistry* paramRegistry;
	
protected:
	virtual void analyzeFunction(ParameterRegistry& paramRegistry, CallInformation& fillOut, llvm::Function& func) = 0;
	
public:
	ParameterIdentificationPass(char& identifier)
	: llvm::FunctionPass(identifier), cc(nullptr), paramRegistry(nullptr)
	{
	}
	
	virtual bool runOnFunction(llvm::Function& fn) override final;
};

// CallingConvention objects can identify parameters in a function following their own rules.
class CallingConvention
{
protected:
	virtual std::unique_ptr<ParameterIdentificationPass> doCreatePass() = 0;
	
public:
	static bool registerCallingConvention(CallingConvention* cc);
	static CallingConvention* getCallingConvention(const std::string& name);
	static CallingConvention* getMatchingCallingConvention(TargetInfo& target, Executable& executable);
	
	virtual const char* getName() const = 0;
	virtual bool matches(TargetInfo& target, Executable& executable) const;
	std::unique_ptr<ParameterIdentificationPass> createPass(ParameterRegistry& registry);
	
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
