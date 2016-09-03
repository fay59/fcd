//
// header_declarations.cpp
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

#include "header_declarations.h"

#include "CodeGenTypes.h"

#include <clang-c/Index.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Basic/Version.h>
#include <clang/CodeGen/ModuleBuilder.h>
#include <clang/Frontend/ASTUnit.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/TextDiagnosticPrinter.h>
#include <clang/Index/CodegenNameGenerator.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/FileSystem.h>

#include <dlfcn.h>

using namespace clang;
using namespace llvm;
using namespace std;

namespace
{
	string getClangResourcesPath()
	{
		Dl_info info;
		if (dladdr(reinterpret_cast<void*>(clang_createTranslationUnit), &info) == 0)
		{
			llvm_unreachable("fcd isn't linked against libclang?!");
		}
		
		SmallString<128> parentPath = sys::path::parent_path(info.dli_fname);
		sys::path::append(parentPath, "clang", CLANG_VERSION_STRING);
		return parentPath.str();
	}
	
	class FunctionDeclarationFinder : public RecursiveASTVisitor<FunctionDeclarationFinder>
	{
		index::CodegenNameGenerator& mangler;
		unordered_map<string, FunctionDecl*>& knownFunctions;
		
	public:
		FunctionDeclarationFinder(index::CodegenNameGenerator& mangler, unordered_map<string, FunctionDecl*>& knownFunctions)
		: mangler(mangler), knownFunctions(knownFunctions)
		{
		}
		
		bool shouldVisitImplicitCode()
		{
			return true;
		}
		
		bool TraverseFunctionDecl(FunctionDecl* fn)
		{
			string mangledName = mangler.getName(fn);
			errs() << "Found " << mangledName << '\n';
			knownFunctions[mangledName] = fn;
			return true;
		}
	};
}

HeaderDeclarations::HeaderDeclarations(llvm::Module& module, unique_ptr<ASTUnit> tu, llvm::IntrusiveRefCntPtr<clang::DiagnosticsEngine> diags)
: module(module), tu(move(tu)), diags(move(diags))
{
}

unique_ptr<HeaderDeclarations> HeaderDeclarations::create(llvm::Module& module, const std::vector<std::string>& headers, raw_ostream& errors)
{
	if (headers.size() == 0)
	{
		return nullptr;
	}
	
	string includeContent;
	raw_string_ostream includer(includeContent);
	for (const auto& header : headers)
	{
		includer << "#include \"" << header << "\"\n";
	}
	includer.flush();
	
	if (auto includeBuffer = MemoryBuffer::getMemBuffer(includeContent, "<fcd>"))
	{
		auto diagOpts = std::make_unique<DiagnosticOptions>();
		diagOpts->TabStop = 4;
		
		auto diagPrinter = new TextDiagnosticPrinter(errors, diagOpts.get());
		IntrusiveRefCntPtr<DiagnosticsEngine> diags(CompilerInstance::createDiagnostics(diagOpts.release(), diagPrinter));
		
		auto clang = std::make_unique<CompilerInvocation>();
		clang->getLangOpts()->SpellChecking = false;
		clang->getTargetOpts().Triple = module.getTargetTriple();
		clang->getFrontendOpts().SkipFunctionBodies = true;
		clang->getFrontendOpts().Inputs.emplace_back(includeBuffer.get(), IK_C);
		clang->getHeaderSearchOpts().ResourceDir = getClangResourcesPath();
		
		FileSystemOptions fsOptions;
		auto fileManager = std::make_unique<FileManager>(fsOptions);
		
		auto pch = std::make_shared<PCHContainerOperations>();
		if (auto tu = ASTUnit::LoadFromCompilerInvocation(clang.get(), pch, diags, fileManager.release(), true))
		{
			unique_ptr<HeaderDeclarations> result(new HeaderDeclarations(module, move(tu), diags));
			if (CodeGenerator* codegen = CreateLLVMCodeGen(*diags, "fcd-headers", clang->getHeaderSearchOpts(), clang->getPreprocessorOpts(), clang->getCodeGenOpts(), module.getContext()))
			{
				codegen->Initialize(result->tu->getASTContext());
				result->codeGenerator.reset(codegen);
				result->typeLowering.reset(new CodeGen::CodeGenTypes(codegen->CGM()));
				index::CodegenNameGenerator mangler(result->tu->getASTContext());
				FunctionDeclarationFinder visitor(mangler, result->knownFunctions);
				visitor.TraverseDecl(result->tu->getASTContext().getTranslationUnitDecl());
				return result;
			}
			else
			{
				errors << "Couldn't create Clang code generator!\n";
			}
		}
		else if (diagPrinter->getNumErrors() == 0)
		{
			errors << "Couldn't create translation unit!\n";
		}
	}
	else
	{
		errors << "Couldn't create memory buffer from list of includes!\n";
	}
	return nullptr;
}

Function* HeaderDeclarations::prototypeForImportName(const string& importName)
{
	if (Function* fn = module.getFunction(importName))
	{
		return fn;
	}
	
	auto iter = knownFunctions.find(importName);
	if (iter == knownFunctions.end())
	{
		return nullptr;
	}
	
	FunctionDecl* funcDecl = iter->second;
	llvm::FunctionType* functionType = typeLowering->GetFunctionType(GlobalDecl(funcDecl));
	
	// Cheating and bringing in CodeGenTypes is fairly cheap and reliable. Unfortunately, CodeGenModules, which is
	// responsible for attribute translation, is a pretty big class with lots of dependencies.
	// That said, while most attributes have a lot of value for compilation, they don't bring that much in for
	// decompilation.
	AttrBuilder attributeBuilder;
	if (funcDecl->hasAttr<ReturnsTwiceAttr>())
	{
		attributeBuilder.addAttribute(Attribute::ReturnsTwice);
	}
	if (funcDecl->hasAttr<NoThrowAttr>())
	{
		attributeBuilder.addAttribute(Attribute::NoUnwind);
	}
	if (funcDecl->hasAttr<NoReturnAttr>())
	{
		attributeBuilder.addAttribute(Attribute::NoReturn);
	}
	if (funcDecl->hasAttr<ConstAttr>())
	{
		attributeBuilder.addAttribute(Attribute::ReadNone);
		attributeBuilder.addAttribute(Attribute::NoUnwind);
	}
	if (funcDecl->hasAttr<PureAttr>())
	{
		attributeBuilder.addAttribute(Attribute::ReadOnly);
		attributeBuilder.addAttribute(Attribute::NoUnwind);
	}
	if (funcDecl->hasAttr<NoAliasAttr>())
	{
		attributeBuilder.addAttribute(Attribute::ArgMemOnly);
		attributeBuilder.addAttribute(Attribute::NoUnwind);
	}
	
	Function* fn = Function::Create(functionType, GlobalValue::ExternalLinkage);
	fn->addAttributes(AttributeSet::FunctionIndex, AttributeSet::get(module.getContext(), AttributeSet::FunctionIndex, attributeBuilder));
	if (funcDecl->hasAttr<RestrictAttr>())
	{
		fn->addAttribute(AttributeSet::ReturnIndex, Attribute::NoAlias);
	}
	
	fn->setName(importName);
	module.getFunctionList().insert(module.getFunctionList().end(), fn);
	return fn;
}

HeaderDeclarations::~HeaderDeclarations()
{
}
