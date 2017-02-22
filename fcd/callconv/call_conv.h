//
// call_conv.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__callconv_call_conv_h
#define fcd__callconv_call_conv_h

#include "executable.h"
#include "params_registry.h"
#include "targetinfo.h"

#include <llvm/IR/Function.h>

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
	virtual bool analyzeFunction(ParameterRegistry& registry, CallInformation& fillOut, llvm::Function& func);
	
	// used for functions without a body (prototypes, imports, vararg calls)
	virtual bool analyzeCallSite(ParameterRegistry& registry, CallInformation& fillOut, llvm::CallSite cs);
	
	// used when a function type can be inferred but no other information is available
	// (usually called by another CC's analyzeCallSite when they identify a function type but don't know
	// what to do with it)
	virtual bool analyzeFunctionType(ParameterRegistry& registry, CallInformation& fillOut, llvm::FunctionType& type);
	
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
		(void) registered;
	}
};

#endif /* fcd__callconv_call_conv_h */
