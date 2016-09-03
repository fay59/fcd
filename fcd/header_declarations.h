//
// header_declarations.h
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
	llvm::IntrusiveRefCntPtr<clang::DiagnosticsEngine> diags;
	
	std::unordered_map<std::string, clang::FunctionDecl*> knownFunctions;
	
	HeaderDeclarations(llvm::Module& module, std::unique_ptr<clang::ASTUnit> tu, llvm::IntrusiveRefCntPtr<clang::DiagnosticsEngine> diags);
	
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

#endif /* header_index_hpp */
