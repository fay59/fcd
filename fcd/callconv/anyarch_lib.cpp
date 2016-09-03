//
// anyarch_lib.cpp
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

#include "anyarch_lib.h"
#include "cc_common.h"
#include "command_line.h"
#include "metadata.h"

#include <llvm/Support/FileSystem.h>

#include <string>
#include <unordered_map>
#include <stdio.h>

using namespace llvm;
using namespace std;

namespace
{
	RegisterCallingConvention<CallingConvention_AnyArch_Library> registerAnyLibrary;
	
	cl::list<std::string> headers("#header", cl::desc("Path of a header file to parse for function declarations. Can be specified multiple times"), whitelist());
}

const char* CallingConvention_AnyArch_Library::name = "any/library";

CXChildVisitResult CallingConvention_AnyArch_Library::visitTopLevel(CXCursor cursor, CXCursor parent)
{
	if (cursor.kind == CXCursor_FunctionDecl)
	{
		const char* functionName = clang_getCString(clang_getCursorSpelling(cursor));
		knownFunctions[functionName] = cursor;
	}
	return CXChildVisit_Continue;
}

CallingConvention_AnyArch_Library::CallingConvention_AnyArch_Library()
: index(nullptr), state(Uninitialized)
{
}

CallingConvention_AnyArch_Library::~CallingConvention_AnyArch_Library()
{
	clang_disposeIndex(index);
}

void CallingConvention_AnyArch_Library::initialize()
{
	if (headers.size() == 0)
	{
		state = Success;
		return;
	}
	
	int fd;
	SmallVector<char, 40> tempFilePath;
	if (auto error = sys::fs::createTemporaryFile("fcd", "c", fd, tempFilePath))
	{
		errs() << "Cannot open temporary file: " << error.message() << '\n';
		errs() << "C header parsing will be disabled.\n";
	}
	else if ((index = clang_createIndex(false, true)))
	{
		raw_fd_ostream includer(fd, true);
		for (const auto& header : headers)
		{
			includer << "#include \"" << header << "\"\n";
		}
		includer.flush();
		
		if (CXTranslationUnit tu = clang_parseTranslationUnit(index, tempFilePath.data(), nullptr, 0, nullptr, 0, CXTranslationUnit_SkipFunctionBodies))
		{
			bool parseSucceeded = true;
			unsigned diagCount = clang_getNumDiagnostics(tu);
			for (int i = 0; i < diagCount; ++i)
			{
				CXDiagnostic diag = clang_getDiagnostic(tu, i);
				CXDiagnosticSeverity severity = clang_getDiagnosticSeverity(diag);
				if (severity == CXDiagnostic_Error || severity == CXDiagnostic_Fatal)
				{
					parseSucceeded = false;
					break;
				}
			}
			
			if (parseSucceeded)
			{
				CXCursor cursor = clang_getTranslationUnitCursor(tu);
				clang_visitChildren(cursor, visitTopLevel, this);
				state = Success;
				return;
			}
			else
			{
				// Assume that the callback of visitChildren printed diagnostics.
				errs() << "C header parsing will be disabled.\n";
			}
		}
		else
		{
			// Assume that clang_createTranslationUnitFromSourceFile printed diagnostics.
			errs() << "C header parsing will be disabled.\n";
		}
	}
	else
	{
		errs() << "Cannot create Clang index. C header parsing will be disabled.\n";
	}
	
	state = Failure;
}

const char* CallingConvention_AnyArch_Library::getName() const
{
	return name;
}

const char* CallingConvention_AnyArch_Library::getHelp() const
{
	return "uses import names and --header files to infer parameters; needs a system CC";
}

bool CallingConvention_AnyArch_Library::matches(TargetInfo &target, Executable &executable) const
{
	// Try to perform initialization here since everything is set up.
	if (state == Uninitialized)
	{
		const_cast<CallingConvention_AnyArch_Library*>(this)->initialize();
	}
	
	// Match nothing.
	return false;
}

bool CallingConvention_AnyArch_Library::analyzeCallSite(ParameterRegistry &registry, CallInformation &fillOut, CallSite cs)
{
	if (auto call = dyn_cast<CallInst>(cs.getInstruction()))
	if (auto function = dyn_cast<Function>(call->getCalledValue()))
	if (auto nameNode = md::getImportName(*function))
	{
		auto name = nameNode->getString();
		auto iter = knownFunctions.find(name.str());
		if (iter != knownFunctions.end())
		{
			bool isVararg = clang_Cursor_isVariadic(iter->second);
			unsigned argCount = clang_Cursor_getNumArguments(iter->second);
			CXType returnType = clang_getResultType(clang_getCursorType(iter->second));
			bool returns = returnType.kind != CXType_Void;
			return hackhack_fillFromParamInfo(function->getContext(), registry, fillOut, returns, argCount, isVararg);
		}
	}
	return false;
}
