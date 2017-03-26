//
// main.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "ast_passes.h"
#include "command_line.h"
#include "errors.h"
#include "executable.h"
#include "header_decls.h"
#include "main.h"
#include "metadata.h"
#include "passes.h"
#include "python_context.h"
#include "params_registry.h"
#include "translation_context.h"

#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/BasicAliasAnalysis.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/ScopedNoAliasAA.h>
#include <llvm/Analysis/TypeBasedAliasAnalysis.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/Process.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Scalar/GVN.h>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <unordered_map>
#include <sstream>
#include <string>
#include <vector>

using namespace llvm;
using namespace std;

#ifdef FCD_DEBUG
[[gnu::used]]
raw_ostream& llvm_errs()
{
	return errs();
}
#endif

namespace
{
	cl::opt<string> inputFile(cl::Positional, cl::desc("<input program>"), cl::Required, whitelist());
	cl::list<unsigned long long> additionalEntryPoints("other-entry", cl::desc("Add entry point from virtual address (can be used multiple times)"), cl::CommaSeparated, whitelist());
	cl::list<bool> partialDisassembly("partial", cl::desc("Only decompile functions specified with --other-entry"), whitelist());
	cl::list<bool> inputIsModule("module-in", cl::desc("Input file is a LLVM module"), whitelist());
	cl::list<bool> outputIsModule("module-out", cl::desc("Output LLVM module"), whitelist());
	
	cl::list<string> additionalPasses("opt", cl::desc("Insert LLVM optimization pass; a pass name ending in .py is interpreted as a Python script. Requires default pass pipeline."), whitelist());
	cl::opt<string> customPassPipeline("opt-pipeline", cl::desc("Customize pass pipeline. Empty string lets you order passes through $EDITOR; otherwise, must be a whitespace-separated list of passes."), cl::init("default"), whitelist());
	
	cl::list<string> headers("header", cl::desc("Path of a header file to parse for function declarations. Can be specified multiple times"), whitelist());
	cl::list<string> frameworks("framework", cl::desc("Path of an Apple framework that fcd should use for declarations. Can be specified multiple times"), whitelist());
	cl::list<string> headerSearchPath("I", cl::desc("Additional directory to search headers in. Can be specified multiple times"), whitelist());
	
	cl::alias additionalEntryPointsAlias("e", cl::desc("Alias for --other-entry"), cl::aliasopt(additionalEntryPoints), whitelist());
	cl::alias partialDisassemblyAlias("p", cl::desc("Alias for --partial"), cl::aliasopt(partialDisassembly), whitelist());
	cl::alias additionalPassesAlias("O", cl::desc("Alias for --opt"), cl::aliasopt(additionalPasses), whitelist());
	cl::alias inputIsModuleAlias("m", cl::desc("Alias for --module-in"), cl::aliasopt(inputIsModule), whitelist());
	cl::alias outputIsModuleAlias("n", cl::desc("Alias for --module-out"), cl::aliasopt(outputIsModule), whitelist());
	
	template<int (*)()> // templated to ensure multiple instatiation of the static variables
	inline int optCount(const cl::list<bool>& list)
	{
		static int count = 0;
		static bool counted = false;
		if (!counted)
		{
			for (bool opt : list)
			{
				count += opt ? 1 : -1;
			}
			counted = true;
		}
		return count;
	}
	
	inline int partialOptCount()
	{
		return optCount<partialOptCount>(partialDisassembly);
	}
	
	inline int moduleInCount()
	{
		return optCount<moduleInCount>(inputIsModule);
	}
	
	inline int moduleOutCount()
	{
		return optCount<moduleOutCount>(outputIsModule);
	}
	
	void pruneOptionList(StringMap<cl::Option*>& list)
	{
		for (auto& pair : list)
		{
			if (!whitelist::isWhitelisted(*pair.second))
			{
				pair.second->setHiddenFlag(cl::ReallyHidden);
			}
		}
	}
	
	template<typename T>
	string errorOf(const ErrorOr<T>& error)
	{
		return error.getError().message();
	}
	
	template<typename TAction>
	size_t forEachCall(Function* callee, unsigned stringArgumentIndex, TAction&& action)
	{
		size_t count = 0;
		for (Use& use : callee->uses())
		{
			if (auto call = dyn_cast<CallInst>(use.getUser()))
			{
				unique_ptr<Instruction> eraseIfNecessary;
				Value* operand = call->getOperand(stringArgumentIndex);
				if (auto constant = dyn_cast<ConstantExpr>(operand))
				{
					eraseIfNecessary.reset(constant->getAsInstruction());
					operand = eraseIfNecessary.get();
				}
				
				if (auto gep = dyn_cast<GetElementPtrInst>(operand))
				if (auto global = dyn_cast<GlobalVariable>(gep->getOperand(0)))
				if (auto dataArray = dyn_cast<ConstantDataArray>(global->getInitializer()))
				{
					action(dataArray->getAsString().str());
					count++;
				}
			}
		}
		return count;
	}
	
	bool refillEntryPoints(const TranslationContext& transl, const EntryPointRepository& entryPoints, map<uint64_t, SymbolInfo>& toVisit, size_t iterations)
	{
		if (isExclusiveDisassembly() || (isPartialDisassembly() && iterations > 1))
		{
			return false;
		}
		
		for (uint64_t entryPoint : transl.getDiscoveredEntryPoints())
		{
			if (auto symbolInfo = entryPoints.getInfo(entryPoint))
			{
				toVisit.insert({entryPoint, *symbolInfo});
			}
		}
		return !toVisit.empty();
	}
	
	class Main
	{
		int argc;
		char** argv;
	
		LLVMContext llvm;
		PythonContext python;
		vector<Pass*> optimizeAndTransformPasses;
		
		static void aliasAnalysisHooks(Pass& pass, Function& fn, AAResults& aar)
		{
			if (auto prgmem = pass.getAnalysisIfAvailable<ProgramMemoryAAWrapperPass>())
			{
				aar.addAAResult(prgmem->getResult());
			}
			if (auto params = pass.getAnalysisIfAvailable<ParameterRegistry>())
			{
				aar.addAAResult(params->getAAResult());
			}
		}
	
		static legacy::PassManager createBasePassManager()
		{
			legacy::PassManager pm;
			pm.add(createTypeBasedAAWrapperPass());
			pm.add(createScopedNoAliasAAWrapperPass());
			pm.add(createBasicAAWrapperPass());
			pm.add(createProgramMemoryAliasAnalysis());
			return pm;
		}
		
		vector<Pass*> createPassesFromList(const vector<string>& passNames)
		{
			vector<Pass*> result;
			PassRegistry* pr = PassRegistry::getPassRegistry();
			for (string passName : passNames)
			{
				auto begin = passName.begin();
				while (begin != passName.end())
				{
					if (isspace(*begin))
					{
						++begin;
					}
					else
					{
						break;
					}
				}
				passName.erase(passName.begin(), begin);
				
				auto rbegin = passName.rbegin();
				while (rbegin != passName.rend())
				{
					if (isspace(*rbegin))
					{
						++rbegin;
					}
					else
					{
						break;
					}
				}
				passName.erase(rbegin.base(), passName.end());
				
				if (passName.size() > 0 && passName[0] != '#')
				{
					auto ext = sys::path::extension(passName);
					if (ext == ".py" || ext == ".pyc" || ext == ".pyo")
					{
						if (auto passOrError = python.createPass(passName))
						{
							result.push_back(passOrError.get());
						}
						else
						{
							cerr << getProgramName() << ": couldn't load " << passName << ": " << errorOf(passOrError) << endl;
							return vector<Pass*>();
						}
					}
					else if (const PassInfo* pi = pr->getPassInfo(passName))
					{
						result.push_back(pi->createPass());
					}
					else
					{
						cerr << getProgramName() << ": couldn't identify pass " << passName << endl;
						return vector<Pass*>();
					}
				}
			}
			
			if (result.size() == 0)
			{
				errs() << getProgramName() << ": empty pass list\n";
			}
			return result;
		}
	
		vector<Pass*> interactivelyEditPassPipeline(const string& editor, const vector<string>& basePasses)
		{
			int fd;
			SmallVector<char, 100> path;
			if (auto errorCode = sys::fs::createTemporaryFile("fcd-pass-pipeline", "txt", fd, path))
			{
				errs() << getProgramName() << ": can't open temporary file for editing: " << errorCode.message() << "\n";
				return vector<Pass*>();
			}
			
			raw_fd_ostream passListOs(fd, true);
			passListOs << "# Enter the name of the LLVM or fcd passes that you want to run on the module.\n";
			passListOs << "# Files starting with a # symbol are ignored.\n";
			passListOs << "# Names ending with .py are assumed to be Python scripts implementing passes.\n";
			for (const string& passName : basePasses)
			{
				passListOs << passName << '\n';
			}
			passListOs.flush();
			
			// shell escape temporary path
			string escapedPath;
			escapedPath.reserve(path.size());
			for (char c : path)
			{
				if (c == '\'' || c == '\\')
				{
					escapedPath.push_back('\\');
				}
				escapedPath.push_back(c);
			}
			
			string editCommand;
			raw_string_ostream(editCommand) << editor << " '" << escapedPath << "'";
			if (int errorCode = system(editCommand.c_str()))
			{
				errs() << getProgramName() << ": interactive pass pipeline: editor returned status code " << errorCode << '\n';
				return vector<Pass*>();
			}
			
			ifstream passListIs(path.data());
			assert(static_cast<bool>(passListIs));
			
			string inputLine;
			vector<string> lines;
			while (getline(passListIs, inputLine))
			{
				lines.push_back(inputLine);
				inputLine.clear();
			}
			if (inputLine.size() != 0)
			{
				lines.push_back(inputLine);
			}
			
			return createPassesFromList(lines);
		}
		
		vector<Pass*> readPassPipelineFromString(const string& argString)
		{
			stringstream ss(argString, ios::in);
			vector<string> passes;
			while (ss)
			{
				passes.emplace_back();
				string& passName = passes.back();
				ss >> passName;
				if (passName.size() == 0 || passName[0] == '#')
				{
					passes.pop_back();
				}
			}
			auto result = createPassesFromList(passes);
			if (result.size() == 0)
			{
				errs() << getProgramName() << ": empty custom pass list\n";
			}
			return result;
		}
	
	public:
		Main(int argc, char** argv)
		: argc(argc), argv(argv), python(argv[0])
		{
			(void) argc;
			(void) this->argc;
		}
	
		string getProgramName() { return sys::path::stem(argv[0]); }
		LLVMContext& getContext() { return llvm; }
	
		ErrorOr<unique_ptr<Executable>> parseExecutable(MemoryBuffer& executableCode)
		{
			auto start = reinterpret_cast<const uint8_t*>(executableCode.getBufferStart());
			auto end = reinterpret_cast<const uint8_t*>(executableCode.getBufferEnd());
			return Executable::parse(start, end);
		}
		
		ErrorOr<unique_ptr<Module>> generateAnnotatedModule(Executable& executable, const string& moduleName = "fcd-out")
		{
			x86_config config64 = { x86_isa64, 8, X86_REG_RIP, X86_REG_RSP, X86_REG_RBP };
			TranslationContext transl(llvm, executable, config64, moduleName);
			
			// Load headers here, since this is the earliest point where we have an executable and a module.
			auto cDecls = HeaderDeclarations::create(
				transl.get(),
				headerSearchPath.begin(),
				headerSearchPath.end(),
				headers.begin(),
				headers.end(),
				frameworks.begin(),
				frameworks.end(),
				errs());
			if (!cDecls)
			{
				return make_error_code(FcdError::Main_HeaderParsingError);
			}
			
			EntryPointRepository entryPoints;
			entryPoints.addProvider(executable);
			entryPoints.addProvider(*cDecls);
			
			md::addIncludedFiles(transl.get(), cDecls->getIncludedFiles());
	
			map<uint64_t, SymbolInfo> toVisit;
			if (isFullDisassembly())
			{
				for (uint64_t address : entryPoints.getVisibleEntryPoints())
				{
					auto symbolInfo = entryPoints.getInfo(address);
					assert(symbolInfo != nullptr);
					toVisit.insert({symbolInfo->virtualAddress, *symbolInfo});
				}
			}
	
			for (uint64_t address : unordered_set<uint64_t>(additionalEntryPoints.begin(), additionalEntryPoints.end()))
			{
				if (auto symbolInfo = entryPoints.getInfo(address))
				{
					toVisit.insert({symbolInfo->virtualAddress, *symbolInfo});
				}
				else
				{
					return make_error_code(FcdError::Main_EntryPointOutOfMappedMemory);
				}
			}
	
			if (toVisit.size() == 0)
			{
				return make_error_code(FcdError::Main_NoEntryPoint);
			}
	
			size_t iterations = 0;
			do
			{
				while (toVisit.size() > 0)
				{
					auto iter = toVisit.begin();
					auto functionInfo = iter->second;
					toVisit.erase(iter);
			
					if (functionInfo.name.size() > 0)
					{
						transl.setFunctionName(functionInfo.virtualAddress, functionInfo.name);
					}
					
					if (Function* fn = transl.createFunction(functionInfo.virtualAddress))
					{
						if (Function* cFunction = cDecls->prototypeForAddress(functionInfo.virtualAddress))
						{
							md::setFinalPrototype(*fn, *cFunction);
						}
					}
					else
					{
						// Couldn't decompile, abort
						return make_error_code(FcdError::Main_DecompilationError);
					}
				}
				iterations++;
			}
			while (refillEntryPoints(transl, entryPoints, toVisit, iterations));
	
			// Perform early optimizations to make the module suitable for analysis
			auto module = transl.take();
			legacy::PassManager phaseOne = createBasePassManager();
			phaseOne.add(createExternalAAWrapperPass(&Main::aliasAnalysisHooks));
			phaseOne.add(createDeadCodeEliminationPass());
			phaseOne.add(createInstructionCombiningPass());
			phaseOne.add(createRegisterPointerPromotionPass());
			phaseOne.add(createGVNPass());
			phaseOne.add(createDeadStoreEliminationPass());
			phaseOne.add(createInstructionCombiningPass());
			phaseOne.add(createGlobalDCEPass());
			phaseOne.run(*module);
	
			// Annotate stubs before returning module
			Function* jumpIntrin = module->getFunction("x86_jump_intrin");
			vector<Function*> functions;
			for (Function& fn : module->getFunctionList())
			{
				if (md::isPrototype(fn))
				{
					continue;
				}
				
				BasicBlock& entry = fn.getEntryBlock();
				auto terminator = entry.getTerminator();
				if (isa<UnreachableInst>(terminator))
				{
					if (auto prev = dyn_cast<CallInst>(terminator->getPrevNode()))
					if (prev->getCalledFunction() == jumpIntrin)
					if (auto load = dyn_cast<LoadInst>(prev->getOperand(2)))
					if (auto constantExpr = dyn_cast<ConstantExpr>(load->getPointerOperand()))
					{
						unique_ptr<Instruction> inst(constantExpr->getAsInstruction());
						if (auto int2ptr = dyn_cast<IntToPtrInst>(inst.get()))
						{
							auto value = cast<ConstantInt>(int2ptr->getOperand(0));
							if (const StubInfo* stubTarget = executable.getStubTarget(value->getLimitedValue()))
							{
								if (Function* cFunction = cDecls->prototypeForImportName(stubTarget->name))
								{
									md::setIsStub(fn);
									md::setFinalPrototype(fn, *cFunction);
								}
								
								// If we identified no function from the header file, this gives the import its real
								// name. Otherwise, it'll prefix the name with some number.
								fn.setName(stubTarget->name);
							}
						}
					}
				}
			}
			return move(module);
		}
		
		bool optimizeAndTransformModule(Module& module, raw_ostream& errorOutput, Executable* executable = nullptr)
		{
			// Phase 3: make into functions with arguments, run codegen.
			auto passManager = createBasePassManager();
			passManager.add(new ExecutableWrapper(executable));
			passManager.add(createParameterRegistryPass());
			passManager.add(createExternalAAWrapperPass(&Main::aliasAnalysisHooks));
			for (Pass* pass : optimizeAndTransformPasses)
			{
				passManager.add(pass);
			}
			passManager.run(module);
	
#ifdef FCD_DEBUG
			if (verifyModule(module, &errorOutput))
			{
				// errors!
				return false;
			}
#endif
			return true;
		}

		bool generateEquivalentPseudocode(Module& module, raw_ostream& output)
		{
			// Run that module through the output pass
			// UnwrapReturns happens after value propagation because value propagation doesn't know that calls
			// are generally not safe to reorder.
			AstBackEnd* backend = createAstBackEnd();
			backend->addPass(new AstRemoveUndef);
			backend->addPass(new AstBranchCombine);
			backend->addPass(new AstSimplifyExpressions);
			backend->addPass(new AstMergeCongruentVariables);
			backend->addPass(new AstBranchCombine);
			backend->addPass(new AstPrint(output, md::getIncludedFiles(module)));
			backend->runOnModule(module);
			return true;
		}
	
		static void initializePasses()
		{
			auto& pr = *PassRegistry::getPassRegistry();
			initializeCore(pr);
			initializeVectorization(pr);
			initializeIPO(pr);
			initializeAnalysis(pr);
			initializeTransformUtils(pr);
			initializeInstCombine(pr);
			initializeScalarOpts(pr);
		
			initializeParameterRegistryPass(pr);
			initializeArgumentRecoveryPass(pr);
		}
		
		bool prepareOptimizationPasses()
		{
			// Default passes
			vector<string> passNames = {
				"globaldce",
				"fixindirects",
				"argrec",
				"sroa",
				"intnarrowing",
				"signext",
				"instcombine",
				"intops",
				"simplifyconditions",
				// <-- custom passes go here with the default pass pipeline
				"instcombine",
				"gvn",
				"simplifycfg",
				"instcombine",
				"gvn",
				"recoverstackframe",
				"dse",
				"sccp",
				"simplifycfg",
				"eliminatecasts",
				"instcombine",
				"memssadle",
				"dse",
				"instcombine",
				"sroa",
				"instcombine",
				"globaldce",
				"simplifycfg",
			};
			
			if (customPassPipeline == "default")
			{
				if (additionalPasses.size() > 0)
				{
					auto extensionPoint = find(passNames.begin(), passNames.end(), "simplifyconditions") + 1;
					passNames.insert(extensionPoint, additionalPasses.begin(), additionalPasses.end());
				}
				optimizeAndTransformPasses = createPassesFromList(passNames);
			}
			else if (customPassPipeline == "")
			{
				if (auto editor = getenv("EDITOR"))
				{
					optimizeAndTransformPasses = interactivelyEditPassPipeline(editor, passNames);
				}
				else
				{
					errs() << getProgramName() << ": environment has no EDITOR variable; pass pipeline can't be edited interactively\n";
					return false;
				}
			}
			else
			{
				optimizeAndTransformPasses = readPassPipelineFromString(customPassPipeline);
			}
			return optimizeAndTransformPasses.size() > 0;
		}
	};
}

bool isFullDisassembly()
{
	return partialOptCount() < 1;
}

bool isPartialDisassembly()
{
	return partialOptCount() == 1;
}

bool isExclusiveDisassembly()
{
	return partialOptCount() > 1;
}

bool isEntryPoint(uint64_t vaddr)
{
	return any_of(additionalEntryPoints.begin(), additionalEntryPoints.end(), [&](uint64_t entryPoint)
	{
		return vaddr == entryPoint;
	});
}

int main(int argc, char** argv)
{
	pruneOptionList(cl::getRegisteredOptions());
	cl::ParseCommandLineOptions(argc, argv, "native program decompiler");
	
	if (customPassPipeline != "default" && additionalPasses.size() > 0)
	{
		errs() << sys::path::filename(argv[0]) << ": additional passes only accepted when using the default pipeline\n";
		errs() << "Specify custom passes using the " << customPassPipeline.ArgStr << " parameter\n";
		return 1;
	}
	
	Main::initializePasses();
	
	Main mainObj(argc, argv);
	string program = mainObj.getProgramName();
	
	// step 0: before even attempting anything, prepare optimization passes
	// (the user won't be happy if we work for 5 minutes only to discover that the optimization passes don't load)
	if (!mainObj.prepareOptimizationPasses())
	{
		return 1;
	}
	
	unique_ptr<Executable> executable;
	unique_ptr<Module> module;
	
	// step one: create annotated module from executable (or load it from .ll)
	ErrorOr<unique_ptr<MemoryBuffer>> bufferOrError(nullptr);
	if (moduleInCount())
	{
		SMDiagnostic errors;
		module = parseIRFile(inputFile, errors, mainObj.getContext());
		if (!module)
		{
			errors.print(argv[0], errs());
			return 1;
		}
	}
	else
	{
		bufferOrError = MemoryBuffer::getFile(inputFile, -1, false);
		if (!bufferOrError)
		{
			cerr << program << ": can't open " << inputFile << ": " << errorOf(bufferOrError) << endl;
			return 1;
		}
		
		auto executableOrError = mainObj.parseExecutable(*bufferOrError.get());
		if (!executableOrError)
		{
			cerr << program << ": couldn't parse " << inputFile << ": " << errorOf(executableOrError) << endl;
			return 1;
		}
		
		executable = move(executableOrError.get());
		string moduleName = sys::path::stem(inputFile);
		auto moduleOrError = mainObj.generateAnnotatedModule(*executable, moduleName);
		if (!moduleOrError)
		{
			cerr << program << ": couldn't build LLVM module out of " << inputFile << ": " << errorOf(moduleOrError) << endl;
			return 1;
		}
		
		module = move(moduleOrError.get());
	}
	
	// Make sure that the module is legal
	size_t errorCount = 0;
	if (Function* assertionFailure = module->getFunction("x86_assertion_failure"))
	{
		errorCount += forEachCall(assertionFailure, 0, [](const string& message) {
			cerr << "translation assertion failure: " << message << endl;
		});
	}
	
	if (errorCount > 0)
	{
		cerr << "incorrect or missing translations; cannot decompile" << endl;
		return 1;
	}
	
	// if we want module output, this is where we stop
	if (moduleOutCount() == 1)
	{
		module->print(outs(), nullptr);
		return 0;
	}
	
	if (moduleInCount() < 2)
	{
		if (!mainObj.optimizeAndTransformModule(*module, errs(), executable.get()))
		{
			return 1;
		}
	}
	
	if (moduleOutCount() > 1)
	{
		module->print(outs(), nullptr);
		return 0;
	}
	
	// step three (final step): emit pseudocode
	return mainObj.generateEquivalentPseudocode(*module, outs()) ? 0 : 1;
}
