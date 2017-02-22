//
// anyarch_anycc.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
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
	virtual const char* getHelp() const override;
	
	virtual bool matches(TargetInfo& target, Executable& executable) const override;
	virtual void getAnalysisUsage(llvm::AnalysisUsage& au) const override;
	virtual bool analyzeFunction(ParameterRegistry& registry, CallInformation& fillOut, llvm::Function& func) override;
};

#endif /* fcd__callconv_anyarch_anycc_h */
