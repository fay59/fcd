//
// header_decls.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
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
	static std::unique_ptr<HeaderDeclarations> create(llvm::Module& module, const std::vector<std::string>& searchPath, std::vector<std::string> headers, const std::vector<std::string>& frameworks, llvm::raw_ostream& errors);
	
	template<typename TSearchPathIter, typename THeaderIter, typename TFrameworkIter>
	static std::unique_ptr<HeaderDeclarations> create(llvm::Module& module, TSearchPathIter searchPathBegin, TSearchPathIter searchPathEnd, THeaderIter headerBegin, THeaderIter headerEnd, TFrameworkIter frameworkBegin, TFrameworkIter frameworkEnd, llvm::raw_ostream& errors)
	{
		return create(module,
			std::vector<std::string>(searchPathBegin, searchPathEnd),
			std::vector<std::string>(headerBegin, headerEnd),
			std::vector<std::string>(frameworkBegin, frameworkEnd),
			errors);
	}
	
	const std::vector<std::string>& getIncludedFiles() const { return includedFiles; }
	llvm::Function* prototypeForImportName(const std::string& importName);
	llvm::Function* prototypeForAddress(uint64_t address);
	
	virtual std::vector<uint64_t> getVisibleEntryPoints() const override;
	virtual const SymbolInfo* getInfo(uint64_t address) const override;
	
	~HeaderDeclarations();
};

#endif /* header_index_hpp */
