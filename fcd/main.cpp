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
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Support/MemoryBuffer.h>
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
	
	cl::alias additionalEntryPointsAlias("e", cl::desc("Alias for --other-entry"), cl::aliasopt(additionalEntryPoints), whitelist());
	cl::alias partialDisassemblyAlias("p", cl::desc("Alias for --partial"), cl::aliasopt(partialDisassembly), whitelist());
	cl::alias additionalPassesAlias("O", cl::desc("Alias for --opt"), cl::aliasopt(additionalPasses), whitelist());
	
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
		PythonContext& python;
		vector<Pass*> additionalPasses;
		
		unique_ptr<translation_context> transl;
		unique_ptr<Executable> executable;
		unique_ptr<Module> module;
		
		legacy::PassManager createBasePassManager()
		{
			legacy::PassManager pm;
			pm.add(createX86TargetInfo());
			pm.add(new ExecutableWrapper(*executable));
			pm.add(createTypeBasedAliasAnalysisPass());
			pm.add(createScopedNoAliasAAPass());
			pm.add(createBasicAliasAnalysisPass());
			pm.add(createAddressSpaceAliasAnalysisPass());
			return pm;
		}
		
		TargetInfo* createX86TargetInfo()
		{
			return transl->create_target_info();
		}
		
		std::error_code makeModule(const string& objectName)
		{
			x86_config config64 = { 8, X86_REG_RIP, X86_REG_RSP, X86_REG_RBP };
			transl.reset(new translation_context(llvm, config64, objectName));
			unordered_map<uint64_t, SymbolInfo> toVisit;
			
			for (uint64_t address : executable->getVisibleEntryPoints())
			{
				auto symbolInfo = executable->getInfo(address);
				assert(symbolInfo != nullptr);
				if (symbolInfo->name != "")
				{
					transl->create_alias(symbolInfo->virtualAddress, symbolInfo->name);
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
				if (auto symbolInfo = executable->getInfo(address))
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
				
				result_function fn_temp = transl->create_function(functionInfo.virtualAddress, functionInfo.memory, executable->end());
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
						if (auto symbolInfo = executable->getInfo(destination))
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
			module = transl->take();
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
			return error_code();
		}
		
		void annotateStubs()
		{
			Function* jumpIntrin = module->getFunction("x86_jump_intrin");
		
			// This may eventually need to be moved to a pass of its own or something.
			vector<Function*> functions;
			for (Function& fn : module->getFunctionList())
			{
				if (fn.isDeclaration())
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
							if (const string* stubTarget = executable->getStubTarget(intValue))
							{
								md::setImportName(fn, *stubTarget);
								fn.setName(*stubTarget);
							}
						}
					}
				}
			}
		}
		
		int decompile(raw_os_ostream& output)
		{
			// Do we still have instances of the unimplemented intrinsic? Bail out here if so.
			size_t errorCount = 0;
			if (Function* unimplemented = module->getFunction("x86_unimplemented"))
			{
				errorCount += forEachCall(unimplemented, 1, [](const string& message) {
					cerr << "translation for instruction '" << message << "' is missing" << endl;
				});
			}
		
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
		
			// Phase two: discover things, simplify other things
			for (int i = 0; i < 2; i++)
			{
				auto phaseTwo = createBasePassManager();
				phaseTwo.add(createParameterRegistryPass());
				phaseTwo.add(createConditionSimplificationPass());
				phaseTwo.add(createGVNPass());
				phaseTwo.add(createDeadStoreEliminationPass());
				phaseTwo.add(createInstructionCombiningPass());
				phaseTwo.add(createCFGSimplificationPass());
				phaseTwo.run(*module);
			
#if DEBUG
				if (verifyModule(*module, &output))
				{
					// errors!
					return 1;
				}
#endif
			}
		
			// Phase 3: make into functions with arguments, run codegen.
			auto phaseThree = createBasePassManager();
			phaseThree.add(createParameterRegistryPass());
			phaseThree.add(createGlobalDCEPass());
			phaseThree.add(createArgumentRecoveryPass());
			phaseThree.add(createModuleThinnerPass());
			phaseThree.add(createSignExtPass());
			phaseThree.add(createConditionSimplificationPass());
			
			// add any additional pass here
			for (Pass* pass : additionalPasses)
			{
				phaseThree.add(pass);
			}
			additionalPasses.clear();
			
			phaseThree.add(createInstructionCombiningPass());
			phaseThree.add(createSROAPass());
			phaseThree.add(createGVNPass());
			phaseThree.add(createDeadStoreEliminationPass());
			phaseThree.add(createIPSCCPPass());
			phaseThree.add(createCFGSimplificationPass());
			phaseThree.add(createGlobalDCEPass());
			phaseThree.run(*module);
		
#ifdef DEBUG
			if (verifyModule(*module, &output))
			{
				// errors!
				return 1;
			}
#endif
		
			// Run that module through the output pass
			auto useAnalysis = new AstVariableReferences;
			AstBackEnd* backend = createAstBackEnd();
			backend->addPass(new AstFlatten);
			backend->addPass(new AstBranchCombine);
			backend->addPass(useAnalysis);
			backend->addPass(new AstPropagateValues(*useAnalysis));
			backend->addPass(new AstRemoveUndef(*useAnalysis));
			backend->addPass(new AstFlatten);
			backend->addPass(new AstBranchCombine);
			backend->addPass(new AstSimplifyExpressions);
		
			legacy::PassManager outputPhase;
			outputPhase.add(createX86TargetInfo());
			outputPhase.add(createSESELoopPass());
			outputPhase.add(createEarlyCSEPass()); // EarlyCSE eliminates redundant PHI nodes
			outputPhase.add(backend);
			outputPhase.run(*module);
		
			for (auto& pair : move(*backend).getResult())
			{
				output << pair.second << '\n';
			}
		
			return 0;
		}
		
		void initializePasses()
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
			initializeTargetInfoPass(pr);
			initializeArgumentRecoveryPass(pr);
			initializeAstBackEndPass(pr);
			initializeSESELoopPass(pr);
		}
		
	public:
		Main(int argc, char** argv, PythonContext& python, LLVMContext& llvm)
		: argc(argc), argv(argv), python(python), llvm(llvm)
		{
			pruneOptionList(cl::getRegisteredOptions());
			cl::ParseCommandLineOptions(argc, argv, "native program decompiler");
			initializePasses();
		}
		
		int run()
		{
			using sys::path::filename;
			auto programName = filename(argv[0]).str();
			
			auto bufferOrError = MemoryBuffer::getFile(inputFile, -1, false);
			if (!bufferOrError)
			{
				cerr << programName << ": can't open " << inputFile << ": " << errorOf(bufferOrError) << endl;
				return 1;
			}
			
			// Build additional pass vector here, nobody likes to be told late that their parameters don't work.
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
						cerr << programName << ": couldn't load " << pass << ": " << errorOf(passOrError) << endl;
						return 1;
					}
				}
				else if (const PassInfo* pi = pr->getPassInfo(pass))
				{
					additionalPasses.push_back(pi->createPass());
				}
				else
				{
					cerr << programName << ": couldn't identify pass " << pass << endl;
					return 1;
				}
			}
			
			unique_ptr<MemoryBuffer>& buffer = bufferOrError.get();
			auto start = reinterpret_cast<const uint8_t*>(buffer->getBufferStart());
			auto end = reinterpret_cast<const uint8_t*>(buffer->getBufferEnd());
			auto executableOrError = Executable::parse(start, end);
			if (!executableOrError)
			{
				cerr << programName << ": couldn't parse " << inputFile << ": " << errorOf(executableOrError) << endl;
				return 1;
			}
			
			this->executable = move(executableOrError.get());
			auto error = makeModule(filename(inputFile));
			if (error)
			{
				cerr << programName << ": couldn't build LLVM module out of " << inputFile << ": " << error << endl;
				return 1;
			}
			
			annotateStubs();
			raw_os_ostream rout(cout);
			decompile(rout);
			return 0;
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
	LLVMContext& llvm = getGlobalContext();
	PythonContext python(argv[0]);
	return Main(argc, argv, python, llvm).run();
}
