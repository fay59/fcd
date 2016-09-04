//
// pass_header_decls.h
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

#ifndef header_index_h
#define header_index_h

#include <llvm/ADT/IntrusiveRefCntPtr.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Pass.h>
#include <llvm/Support/raw_ostream.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace clang
{
	class ASTUnit;
	class CodeGenerator;
	namespace CodeGen
	{
		// Header for CodeGenTypes pulled from Clang source (nasty!)
		class CodeGenTypes;
	}
	class FunctionDecl;
	class DiagnosticsEngine;
}

class HeaderDeclarations
{
	llvm::Module& module;
	std::unique_ptr<clang::ASTUnit> tu;
	std::unique_ptr<clang::CodeGenerator> codeGenerator;
	std::unique_ptr<clang::CodeGen::CodeGenTypes> typeLowering;
	
	std::unordered_map<std::string, clang::FunctionDecl*> knownFunctions;
	
	HeaderDeclarations(llvm::Module& module, std::unique_ptr<clang::ASTUnit> tu);
	
public:
	static std::unique_ptr<HeaderDeclarations> create(llvm::Module& module, const std::vector<std::string>& headers, llvm::raw_ostream& errors);
	
	template<typename TIter>
	static std::unique_ptr<HeaderDeclarations> create(llvm::Module& module, TIter begin, TIter end, llvm::raw_ostream& errors)
	{
		return create(module, std::vector<std::string>(begin, end), errors);
	}
	
	llvm::Function* prototypeForImportName(const std::string& importName);
	
	~HeaderDeclarations();
};

class HeaderDeclarationsWrapper : public llvm::ImmutablePass
{
	HeaderDeclarations* decls;
	
public:
	static char ID;
	
	HeaderDeclarationsWrapper(HeaderDeclarations* decls)
	: llvm::ImmutablePass(ID), decls(decls)
	{
	}
	
	HeaderDeclarations* getDeclarations() { return decls; }
};

namespace llvm
{
	template<>
	inline Pass *callDefaultCtor<HeaderDeclarationsWrapper>() { return nullptr; }
}

#endif /* header_index_hpp */
