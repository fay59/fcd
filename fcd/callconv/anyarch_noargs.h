//
// anyarch_noargs.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef anyarch_noargs_hpp
#define anyarch_noargs_hpp

#include "call_conv.h"
#include "params_registry.h"

class CallingConvention_AnyArch_NoArgs : public CallingConvention
{
public:
	static const char* name;
	
	virtual const char* getName() const override;
	virtual const char* getHelp() const override;
	
	virtual bool matches(TargetInfo& target, Executable& executable) const override;
	virtual bool analyzeFunction(ParameterRegistry& registry, CallInformation& fillOut, llvm::Function& func) override;
	virtual bool analyzeFunctionType(ParameterRegistry& registry, CallInformation& fillOut, llvm::FunctionType& type) override;
	virtual bool analyzeCallSite(ParameterRegistry& registry, CallInformation& fillOut, llvm::CallSite cs) override;
};

#endif /* anyarch_noargs_hpp */
