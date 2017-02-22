//
// header_decls.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "header_decls.h"

#include "CodeGenTypes.h"

#include <clang-c/Index.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Basic/Version.h>
#include <clang/CodeGen/ModuleBuilder.h>
#include <clang/Frontend/ASTUnit.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/TextDiagnosticPrinter.h>
#include <clang/Index/CodegenNameGenerator.h>
#include <llvm/IR/CallingConv.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/FileSystem.h>

#include <dlfcn.h>

using namespace clang;
using namespace llvm;
using namespace std;

// Default include paths are handled by drivers, so we run a nasty pre-build script to get them.
extern "C" {
	extern const char* defaultHeaderSearchPathList[];
	extern const char* defaultFrameworkSearchPathList[];
}

namespace
{
#define CC_LOOKUP(CLANG_CC, LLVM_CC) [static_cast<size_t>(CLANG_CC)] = llvm::CallingConv::LLVM_CC
	constexpr llvm::CallingConv::ID ccLookupTable[] = {
		CC_LOOKUP(CC_C, C),
		CC_LOOKUP(CC_X86StdCall, X86_StdCall),
		CC_LOOKUP(CC_X86FastCall, X86_FastCall),
		CC_LOOKUP(CC_X86ThisCall, X86_ThisCall),
		CC_LOOKUP(CC_X86VectorCall, X86_VectorCall),
		CC_LOOKUP(CC_X86_64Win64, X86_64_Win64),
		CC_LOOKUP(CC_X86_64SysV, X86_64_SysV),
		CC_LOOKUP(CC_AAPCS, ARM_AAPCS),
		CC_LOOKUP(CC_AAPCS_VFP, ARM_AAPCS_VFP),
		CC_LOOKUP(CC_IntelOclBicc, Intel_OCL_BI),
		CC_LOOKUP(CC_SpirFunction, SPIR_FUNC),
		CC_LOOKUP(CC_Swift, Swift),
		CC_LOOKUP(CC_PreserveMost, PreserveMost),
		CC_LOOKUP(CC_PreserveAll, PreserveAll),
	};
#undef CC_LOOKUP
	
	template<typename T, size_t N>
	constexpr size_t countof(const T (&)[N])
	{
		return N;
	}
	
	llvm::CallingConv::ID lookupCallingConvention(clang::CallingConv cc)
	{
		size_t index = static_cast<size_t>(cc);
		return index < countof(ccLookupTable) ? ccLookupTable[index] : llvm::CallingConv::C;
	}
	
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
	
	string getSelfPath()
	{
		Dl_info info;
		if (dladdr(reinterpret_cast<void*>(getSelfPath), &info) == 0)
		{
			llvm_unreachable("linker doesn't know where executable itself is?!");
		}
		return info.dli_fname;
	}
	
	class FunctionDeclarationFinder : public RecursiveASTVisitor<FunctionDeclarationFinder>
	{
		index::CodegenNameGenerator& mangler;
		unordered_map<string, FunctionDecl*>& knownImports;
		unordered_map<uint64_t, HeaderDeclarations::Export>& knownExports;
		
	public:
		FunctionDeclarationFinder(index::CodegenNameGenerator& mangler, unordered_map<string, FunctionDecl*>& knownImports, unordered_map<uint64_t, HeaderDeclarations::Export>& knownExports)
		: mangler(mangler), knownImports(knownImports), knownExports(knownExports)
		{
		}
		
		bool shouldVisitImplicitCode()
		{
			return true;
		}
		
		bool TraverseFunctionDecl(FunctionDecl* fn)
		{
			string mangledName = mangler.getName(fn);
			
			bool foundAddress = false;
			static const char fcdPrefix[] = "fcd.";
			static const char addressPrefix[] = "fcd.virtualaddress:";
			for (auto attribute : fn->specific_attrs<AnnotateAttr>())
			{
				StringRef value = attribute->getAnnotation();
				if (value.startswith(addressPrefix))
				{
					char* endPointer;
					string addressString = value.substr(sizeof addressPrefix - 1).str();
					uint64_t address = strtoull(addressString.c_str(), &endPointer, 0);
					if (*endPointer == 0)
					{
						auto& exported = knownExports[address];;
						if (exported.decl != nullptr)
						{
							errs() << "Function " << mangledName << " replaces function " << exported.name << " at address ";
							errs().write_hex(address);
							errs() << '\n';
						}
						exported.name = mangledName;
						exported.virtualAddress = address;
						exported.decl = fn;
					}
				}
				else if (value.startswith(fcdPrefix))
				{
					errs() << "Function " << mangledName << " has unknown fcd attribute annotation " << value << '\n';
				}
			}
			
			if (!foundAddress)
			{
				knownImports[mangledName] = fn;
			}
			return true;
		}
	};
}

HeaderDeclarations::HeaderDeclarations(llvm::Module& module, unique_ptr<ASTUnit> tu, vector<string> includedFiles)
: module(module), tu(move(tu)), includedFiles(move(includedFiles))
{
}

unique_ptr<HeaderDeclarations> HeaderDeclarations::create(llvm::Module& module, const vector<string>& searchPath, vector<string> headers, const vector<string>& frameworks, raw_ostream& errors)
{
	if (headers.size() == 0)
	{
		// No headers? No problem.
		return unique_ptr<HeaderDeclarations>(new HeaderDeclarations(module, nullptr, move(headers)));
	}
	
	string includeContent;
	raw_string_ostream includer(includeContent);
	includer << "#define FCD_ADDRESS(x) __attribute__((annotate(\"fcd.virtualaddress:\" #x)))\n";
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
		auto diags = CompilerInstance::createDiagnostics(diagOpts.release(), diagPrinter);
		
		IntrusiveRefCntPtr<CompilerInvocation> clang;
		{
			// It might seem lazy to use CreateFromArgs to specify frameworks, but no one has been able to tell me how to
			// do it without using -framework.
			vector<string> invocationArgs = { getSelfPath() };
			for (const char** includePathIter = defaultFrameworkSearchPathList; *includePathIter != nullptr; ++includePathIter)
			{
				invocationArgs.emplace_back();
				raw_string_ostream(invocationArgs.back()) << "-F" << *includePathIter;
			}
			
			for (const auto& framework : frameworks)
			{
				invocationArgs.push_back("-framework");
				invocationArgs.push_back(framework);
			}
			
			invocationArgs.push_back("dummy.c");
			
			vector<const char*> cInvocationArgs;
			for (const auto& arg : invocationArgs)
			{
				cInvocationArgs.push_back(arg.c_str());
			}
			
			auto frameworkArgsArrayRef = makeArrayRef(&*cInvocationArgs.begin(), &*cInvocationArgs.end());
			clang = createInvocationFromCommandLine(frameworkArgsArrayRef, diags);
		}
		
		if (clang)
		{
			clang->getLangOpts()->SpellChecking = false;
			clang->getTargetOpts().Triple = module.getTargetTriple();
			
			auto& searchOpts = clang->getHeaderSearchOpts();
			searchOpts.ResourceDir = getClangResourcesPath();
			
			// Search user directories first.
			for (const auto& includeDir : searchPath)
			{
				// FIXME: we're adding the search paths as System, but we really mean to add them to Quoted and disable
				// diagnostics.
				searchOpts.AddPath(includeDir, frontend::System, false, true);
			}
			
			// Add system-default search paths.
			for (const char** includePathIter = defaultHeaderSearchPathList; *includePathIter != nullptr; ++includePathIter)
			{
				searchOpts.AddPath(*includePathIter, frontend::System, false, true);
			}
			
			// Add current directory last.
			searchOpts.AddPath(".", frontend::System, false, true);
			
			auto& frontendOpts = clang->getFrontendOpts();
			frontendOpts.SkipFunctionBodies = true;
			frontendOpts.Inputs.clear();
			frontendOpts.Inputs.emplace_back(includeBuffer.release(), IK_C);
			
			auto pch = std::make_shared<PCHContainerOperations>();
			auto tu = ASTUnit::LoadFromCompilerInvocation(clang.get(), pch, diags, new FileManager(FileSystemOptions()), true);
			if (diagPrinter->getNumErrors() == 0)
			{
				if (tu)
				{
					unique_ptr<HeaderDeclarations> result(new HeaderDeclarations(module, move(tu), move(headers)));
					if (CodeGenerator* codegen = CreateLLVMCodeGen(*diags, "fcd-headers", clang->getHeaderSearchOpts(), clang->getPreprocessorOpts(), clang->getCodeGenOpts(), module.getContext()))
					{
						codegen->Initialize(result->tu->getASTContext());
						result->codeGenerator.reset(codegen);
						result->typeLowering.reset(new CodeGen::CodeGenTypes(codegen->CGM()));
						index::CodegenNameGenerator mangler(result->tu->getASTContext());
						FunctionDeclarationFinder visitor(mangler, result->knownImports, result->knownExports);
						visitor.TraverseDecl(result->tu->getASTContext().getTranslationUnitDecl());
						return result;
					}
					else
					{
						errors << "Couldn't create Clang code generator!\n";
					}
				}
				else
				{
					errors << "Couldn't parse header files!\n";
					return nullptr;
				}
			}
			// no else: we've already printed the reason that we won't parse headers.
		}
		else
		{
			errors << "Couldn't create compiler instance with provided framework arguments!\n";
		}
	}
	else
	{
		errors << "Couldn't create memory buffer from list of includes!\n";
	}
	return nullptr;
}

Function* HeaderDeclarations::prototypeForDeclaration(FunctionDecl& decl)
{
	llvm::FunctionType* functionType = typeLowering->GetFunctionType(GlobalDecl(&decl));
	
	// Cheating and bringing in CodeGenTypes is fairly cheap and reliable. Unfortunately, CodeGenModules, which is
	// responsible for attribute translation, is a pretty big class with lots of dependencies.
	// That said, while most attributes have a lot of value for compilation, they don't bring that much in for
	// decompilation.
	AttrBuilder attributeBuilder;
	if (decl.isNoReturn())
	{
		attributeBuilder.addAttribute(Attribute::NoReturn);
	}
	if (decl.hasAttr<ConstAttr>())
	{
		attributeBuilder.addAttribute(Attribute::ReadNone);
		attributeBuilder.addAttribute(Attribute::NoUnwind);
	}
	if (decl.hasAttr<PureAttr>())
	{
		attributeBuilder.addAttribute(Attribute::ReadOnly);
		attributeBuilder.addAttribute(Attribute::NoUnwind);
	}
	if (decl.hasAttr<NoAliasAttr>())
	{
		attributeBuilder.addAttribute(Attribute::ArgMemOnly);
		attributeBuilder.addAttribute(Attribute::NoUnwind);
	}
	
	Function* fn = Function::Create(functionType, GlobalValue::ExternalLinkage);
	fn->addAttributes(AttributeSet::FunctionIndex, AttributeSet::get(module.getContext(), AttributeSet::FunctionIndex, attributeBuilder));
	if (decl.hasAttr<RestrictAttr>())
	{
		fn->addAttribute(AttributeSet::ReturnIndex, Attribute::NoAlias);
	}
	
	// If we know the calling convention, apply it here
	auto prototype = decl.getType()->getCanonicalTypeUnqualified().getAs<FunctionProtoType>();
	auto callingConvention = lookupCallingConvention(prototype->getExtInfo().getCC());
	
	fn->setCallingConv(callingConvention);
	module.getFunctionList().insert(module.getFunctionList().end(), fn);
	return fn;
}

Function* HeaderDeclarations::prototypeForImportName(const string& importName)
{
	if (Function* fn = module.getFunction(importName))
	{
		return fn;
	}
	
	auto iter = knownImports.find(importName);
	if (iter == knownImports.end())
	{
		return nullptr;
	}
	
	return prototypeForDeclaration(*iter->second);
}

Function* HeaderDeclarations::prototypeForAddress(uint64_t address)
{
	auto iter = knownExports.find(address);
	if (iter == knownExports.end())
	{
		return nullptr;
	}
	
	return prototypeForDeclaration(*iter->second.decl);
}

vector<uint64_t> HeaderDeclarations::getVisibleEntryPoints() const
{
	vector<uint64_t> entryPoints;
	for (const auto& pair : knownExports)
	{
		entryPoints.push_back(pair.first);
	}
	sort(entryPoints.begin(), entryPoints.end());
	return entryPoints;
}

const SymbolInfo* HeaderDeclarations::getInfo(uint64_t address) const
{
	auto iter = knownExports.find(address);
	return iter == knownExports.end() ? nullptr : &iter->second;
}

HeaderDeclarations::~HeaderDeclarations()
{
}
