//
// anyarch_lib.h
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

#ifndef fcd__callconv_anyarch_lib_h
#define fcd__callconv_anyarch_lib_h

#include "call_conv.h"
#include "params_registry.h"

#include <clang-c/Index.h>
#include <string>
#include <unordered_map>

class CallingConvention_AnyArch_Library : public CallingConvention
{
	enum InitializationState
	{
		Uninitialized,
		Success,
		Failure
	};
	
	InitializationState state;
	CXIndex index;
	std::unordered_map<std::string, CXCursor> knownFunctions;
	
	static CXChildVisitResult visitTopLevel(CXCursor cursor, CXCursor parent, CXClientData that)
	{
		return reinterpret_cast<CallingConvention_AnyArch_Library*>(that)->visitTopLevel(cursor, parent);
	}
	
	void initialize();
	CXChildVisitResult visitTopLevel(CXCursor cursor, CXCursor parent);
	
public:
	static const char* name;
	
	CallingConvention_AnyArch_Library();
	~CallingConvention_AnyArch_Library();
	
	virtual const char* getName() const override;
	virtual const char* getHelp() const override;
	
	virtual bool matches(TargetInfo& target, Executable& executable) const override;
	virtual bool analyzeCallSite(ParameterRegistry& registry, CallInformation& fillOut, llvm::CallSite cs) override;
};

#endif /* fcd__callconv_anyarch_lib_h */
