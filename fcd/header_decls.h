//
// header_decls.h
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

#include "entry_points.h"

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
}

class HeaderDeclarations : public EntryPointProvider
{
public:
	struct Export : public SymbolInfo
	{
		clang::FunctionDecl* decl;
	};
	
private:
	llvm::Module& module;
	std::unique_ptr<clang::ASTUnit> tu;
	std::unique_ptr<clang::CodeGenerator> codeGenerator;
	std::unique_ptr<clang::CodeGen::CodeGenTypes> typeLowering;
	
	std::vector<std::string> includedFiles;
	std::unordered_map<std::string, clang::FunctionDecl*> knownImports;
	std::unordered_map<uint64_t, Export> knownExports;
	
	HeaderDeclarations(llvm::Module& module, std::unique_ptr<clang::ASTUnit> tu, std::vector<std::string> includedFiles);
	
	llvm::Function* prototypeForDeclaration(clang::FunctionDecl& decl);
	
public:
	static std::unique_ptr<HeaderDeclarations> create(llvm::Module& module, const std::vector<std::string>& searchPath, std::vector<std::string> headers, llvm::raw_ostream& errors);
	
	template<typename TSearchPathIter, typename THeaderIter>
	static std::unique_ptr<HeaderDeclarations> create(llvm::Module& module, TSearchPathIter searchPathBegin, TSearchPathIter searchPathEnd, THeaderIter headerBegin, THeaderIter headerEnd, llvm::raw_ostream& errors)
	{
		return create(module, std::vector<std::string>(searchPathBegin, searchPathEnd), std::vector<std::string>(headerBegin, headerEnd), errors);
	}
	
	const std::vector<std::string>& getIncludedFiles() const { return includedFiles; }
	llvm::Function* prototypeForImportName(const std::string& importName);
	llvm::Function* prototypeForAddress(uint64_t address);
	
	virtual std::vector<uint64_t> getVisibleEntryPoints() const override;
	virtual const SymbolInfo* getInfo(uint64_t address) const override;
	
	~HeaderDeclarations();
};

#endif /* header_index_hpp */
