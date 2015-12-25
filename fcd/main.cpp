//
// main.cpp
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

#include "command_line.h"
#include "llvm_warnings.h"
#include "main.h"
#include "metadata.h"
#include "params_registry.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Analysis/Passes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/Scalar.h>
SILENCE_LLVM_WARNINGS_END()

#include <iomanip>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <string>
#include <vector>

#include "ast_passes.h"
#include "errors.h"
#include "executable.h"
#include "passes.h"
#include "pass_python.h"
#include "translation_context.h"

using namespace llvm;
using namespace std;

namespace
{
	cl::opt<string> inputFile(cl::Positional, cl::desc("<input program>"), cl::Required, whitelist());
	cl::list<uint64_t> additionalEntryPoints("other-entry", cl::desc("Add entry point from virtual address (can be used multiple times)"), cl::CommaSeparated, whitelist());
	cl::list<bool> partialDisassembly("partial", cl::desc("Only decompile functions specified with --other-entry"), whitelist());
	cl::list<string> additionalPasses("opt", cl::desc("Insert LLVM optimization pass; a pass name ending in .py is interpreted as a Python script"), whitelist());
	cl::opt<bool> inputIsModule("module-in", cl::desc("Input file is a LLVM module"), whitelist());
	cl::opt<bool> outputIsModule("module-out", cl::desc("Output LLVM module"), whitelist());
	
	cl::alias additionalEntryPointsAlias("e", cl::desc("Alias for --other-entry"), cl::aliasopt(additionalEntryPoints), whitelist());
	cl::alias partialDisassemblyAlias("p", cl::desc("Alias for --partial"), cl::aliasopt(partialDisassembly), whitelist());
	cl::alias additionalPassesAlias("O", cl::desc("Alias for --opt"), cl::aliasopt(additionalPasses), whitelist());
	cl::alias inputIsModuleAlias("m", cl::desc("Alias for --module-in"), cl::aliasopt(inputIsModule), whitelist());
	cl::alias outputIsModuleAlias("n", cl::desc("Alias for --module-out"), cl::aliasopt(outputIsModule), whitelist());
	
	inline int partialOptCount()
	{
		static int count = 0;
		static bool counted = false;
		if (!counted)
		{
			for (bool opt : partialDisassembly)
			{
				count += opt ? 1 : -1;
			}
			counted = true;
		}
		return count;
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
		assert(!error);
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
	
	class Main
	{
		int argc;
		char** argv;
	
		LLVMContext& llvm;
		PythonContext python;
		vector<Pass*> additionalPasses;
	
		static legacy::PassManager createBasePassManager()
		{
			legacy::PassManager pm;
			pm.add(createTypeBasedAliasAnalysisPass());
			pm.add(createScopedNoAliasAAPass());
			pm.add(createBasicAliasAnalysisPass());
			pm.add(createProgramMemoryAliasAnalysis());
			return pm;
		}
	
	public:
		Main(int argc, char** argv)
		: argc(argc), argv(argv), llvm(getGlobalContext()), python(argv[0])
		{
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
			translation_context transl(llvm, config64, moduleName);
	
			unordered_map<uint64_t, SymbolInfo> toVisit;
			for (uint64_t address : executable.getVisibleEntryPoints())
			{
				auto symbolInfo = executable.getInfo(address);
				assert(symbolInfo != nullptr);
				if (symbolInfo->name != "")
				{
					transl.create_alias(symbolInfo->virtualAddress, symbolInfo->name);
				}
		
				// Entry points are always considered when naming symbols, but only used in full disassembly mode.
				// Otherwise, we expect symbols to be specified with the command line.
				if (isFullDisassembly())
				{
					toVisit.insert({symbolInfo->virtualAddress, *symbolInfo});
				}
			}
	
			unordered_set<uint64_t> entryPoints(additionalEntryPoints.begin(), additionalEntryPoints.end());
			for (uint64_t address : entryPoints)
			{
				if (auto symbolInfo = executable.getInfo(address))
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
	
			unordered_map<uint64_t, result_function> functions;
	
			while (toVisit.size() > 0)
			{
				auto iter = toVisit.begin();
				auto functionInfo = iter->second;
				toVisit.erase(iter);
		
				result_function fn_temp = transl.create_function(functionInfo.virtualAddress, functionInfo.memory, executable.end());
				auto inserted_function = functions.insert(make_pair(functionInfo.virtualAddress, move(fn_temp))).first;
				result_function& fn = inserted_function->second;
		
				// In full disassembly, unconditionally add callees to list of functions to visit.
				// In partial disassembly, add callees to list of functions to visit only if the caller is an entry point.
				//  (This allows us to identify called imports, since imports need to be analyzed to be identified.)
				// In exclusive disassembly, never add callees.
		
				if (!isExclusiveDisassembly())
				{
					for (auto callee = fn.callees_begin(); callee != fn.callees_end(); callee++)
					{
						auto destination = *callee;
						if (functions.find(destination) == functions.end())
						if (auto symbolInfo = executable.getInfo(destination))
						if (isFullDisassembly() || entryPoints.count(functionInfo.virtualAddress) != 0)
						{
							toVisit.insert({destination, *symbolInfo});
						}
					}
				}
			}
	
			for (auto& pair : functions)
			{
				pair.second.take();
			}
	
			// Perform early optimizations to make the module suitable for analysis
			auto module = transl.take();
			legacy::PassManager phaseOne = createBasePassManager();
			phaseOne.add(createInstructionCombiningPass());
			phaseOne.add(createCFGSimplificationPass());
			phaseOne.add(createRegisterPointerPromotionPass());
			phaseOne.add(createGVNPass());
			phaseOne.add(createDeadStoreEliminationPass());
			phaseOne.add(createInstructionCombiningPass());
			phaseOne.add(createCFGSimplificationPass());
			phaseOne.add(createGlobalDCEPass());
			phaseOne.run(*module);
	
			// Annotate stubs before returning module
			annotateStubs(executable, *module);
			return move(module);
		}

		void annotateStubs(Executable& executable, Module& module)
		{
			Function* jumpIntrin = module.getFunction("x86_jump_intrin");

			// This may eventually need to be moved to a pass of its own or something.
			vector<Function*> functions;
			for (Function& fn : module.getFunctionList())
			{
				if (md::isPrototype(fn))
				{
					continue;
				}
	
				BasicBlock& entry = fn.getEntryBlock();
				auto terminator = entry.getTerminator();
				if (isa<ReturnInst>(terminator))
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
							auto intValue = value->getLimitedValue();
							if (const string* stubTarget = executable.getStubTarget(intValue))
							{
								md::setImportName(fn, *stubTarget);
								fn.setName(*stubTarget);
							}
						}
					}
				}
			}
		}

		bool optimizeAndTransformModule(Module& module, raw_ostream& errorOutput, Executable* executable = nullptr)
		{
			// Do we still have instances of the unimplemented intrinsic? Bail out here if so.
			size_t errorCount = 0;
			if (Function* unimplemented = module.getFunction("x86_unimplemented"))
			{
				errorCount += forEachCall(unimplemented, 1, [](const string& message) {
					cerr << "translation for instruction '" << message << "' is missing" << endl;
				});
			}
	
			if (Function* assertionFailure = module.getFunction("x86_assertion_failure"))
			{
				errorCount += forEachCall(assertionFailure, 0, [](const string& message) {
					cerr << "translation assertion failure: " << message << endl;
				});
			}
	
			if (errorCount > 0)
			{
				cerr << "incorrect or missing translations; cannot decompile" << endl;
				return false;
			}
	
			// Phase two: discover things, simplify other things
			for (int i = 0; i < 2; i++)
			{
				auto phaseTwo = createBasePassManager();
				phaseTwo.add(new ExecutableWrapper(executable));
				phaseTwo.add(createParameterRegistryPass());
				phaseTwo.add(createConditionSimplificationPass());
				phaseTwo.add(createGVNPass());
				phaseTwo.add(createDeadStoreEliminationPass());
				phaseTwo.add(createInstructionCombiningPass());
				phaseTwo.add(createCFGSimplificationPass());
				phaseTwo.run(module);
		
#if DEBUG
				if (verifyModule(module, &errorOutput))
				{
					// errors!
					return false;
				}
#endif
			}
	
			// Phase 3: make into functions with arguments, run codegen.
			auto phaseThree = createBasePassManager();
			phaseThree.add(new ExecutableWrapper(executable));
			phaseThree.add(createParameterRegistryPass());
			phaseThree.add(createGlobalDCEPass());
			phaseThree.add(createFixIndirectsPass());
			phaseThree.add(createArgumentRecoveryPass());
			phaseThree.add(createModuleThinnerPass());
			phaseThree.add(createSignExtPass());
			phaseThree.add(createConditionSimplificationPass());
	
			// XXX: do something about this, I keep coming back to add passes to
			// accommodate my custom passes
			
			// add any additional pass here
			for (Pass* pass : additionalPasses)
			{
				phaseThree.add(pass);
			}
			additionalPasses.clear();
	
			phaseThree.add(createInstructionCombiningPass());
			phaseThree.add(createSROAPass());
			phaseThree.add(createInstructionCombiningPass());
			phaseThree.add(createGVNPass());
			phaseThree.add(createIdentifyLocalsPass());
			phaseThree.add(createDeadStoreEliminationPass());
			phaseThree.add(createIPSCCPPass());
			phaseThree.add(createCFGSimplificationPass());
			phaseThree.add(createDeadStoreEliminationPass());
			phaseThree.add(createSROAPass());
			phaseThree.add(createInstructionCombiningPass());
			phaseThree.add(createGlobalDCEPass());
			phaseThree.add(createCFGSimplificationPass());
			phaseThree.run(module);
	
#ifdef DEBUG
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
			backend->addPass(new AstFlatten);
			backend->addPass(new AstBranchCombine);
			backend->addPass(new AstPropagateValues);
			backend->addPass(new AstRemoveUndef);
			backend->addPass(new AstFlatten);
			backend->addPass(new AstBranchCombine);
			backend->addPass(new AstSimplifyExpressions);
			backend->addPass(new AstPrint(output));
	
			legacy::PassManager outputPhase;
			outputPhase.add(createSESELoopPass());
			outputPhase.add(createEarlyCSEPass()); // EarlyCSE eliminates redundant PHI nodes
			outputPhase.add(backend);
			outputPhase.run(module);
			return true;
		}
	
		static void initializePasses()
		{
			auto& pr = *PassRegistry::getPassRegistry();
			initializeCore(pr);
			initializeVectorization(pr);
			initializeIPO(pr);
			initializeAnalysis(pr);
			initializeIPA(pr);
			initializeTransformUtils(pr);
			initializeInstCombine(pr);
			initializeScalarOpts(pr);
		
			// TODO: remove when MemorySSA goes mainstream
			initializeMemorySSAPrinterPassPass(pr);
			initializeMemorySSALazyPass(pr);
		
			initializeParameterRegistryPass(pr);
			initializeArgumentRecoveryPass(pr);
			initializeAstBackEndPass(pr);
			initializeSESELoopPass(pr);
		}
	
		bool prepareOptimizationPasses()
		{
			PassRegistry* pr = PassRegistry::getPassRegistry();
			for (const string& pass : ::additionalPasses)
			{
				auto ext = sys::path::extension(pass);
				if (ext == ".py" || ext == ".pyc" || ext == ".pyo")
				{
					if (auto passOrError = python.createPass(pass))
					{
						additionalPasses.push_back(passOrError.get());
					}
					else
					{
						cerr << getProgramName() << ": couldn't load " << pass << ": " << errorOf(passOrError) << endl;
						return false;
					}
				}
				else if (const PassInfo* pi = pr->getPassInfo(pass))
				{
					additionalPasses.push_back(pi->createPass());
				}
				else
				{
					cerr << getProgramName() << ": couldn't identify pass " << pass << endl;
					return false;
				}
			}
			return true;
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
	if (inputIsModule)
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
		auto bufferOrError = MemoryBuffer::getFile(inputFile, -1, false);
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
			cerr << program << ": couldn't build LLVM module out of " << inputFile << ": " << errorOf(executableOrError) << endl;
			return 1;
		}
		
		module = move(moduleOrError.get());
	}
	
	// if we want module output, this is where we stop
	if (outputIsModule)
	{
		module->print(outs(), nullptr);
		return 0;
	}
	
	// step two: optimize module
	if (!mainObj.optimizeAndTransformModule(*module, errs(), executable.get()))
	{
		return 1;
	}
	
	// step three (final step): emit pseudocode
	return mainObj.generateEquivalentPseudocode(*module, outs()) ? 0 : 1;
}
