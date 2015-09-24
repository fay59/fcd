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

#include "ast_passes.h"
#include "errors.h"
#include "executable.h"
#include "passes.h"
#include "translation_context.h"
#include "x86_register_map.h"

using namespace llvm;
using namespace std;

namespace
{
	cl::opt<string> inputFile(cl::Positional, cl::desc("<input program>"), cl::Required, whitelist());
	cl::list<uint64_t> additionalEntryPoints("other-entry", cl::desc("Add entry point from virtual address (can be used multiple times)"), cl::CommaSeparated, whitelist());
	cl::alias additionalEntryPointsAlias("e", cl::desc("Alias for --other-entry"), cl::aliasopt(additionalEntryPoints), whitelist());
	
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
	
	legacy::PassManager createBasePassManager()
	{
		legacy::PassManager pm;
		pm.add(createTypeBasedAliasAnalysisPass());
		pm.add(createScopedNoAliasAAPass());
		pm.add(createBasicAliasAnalysisPass());
		pm.add(createAddressSpaceAliasAnalysisPass());
		return pm;
	}
	
	TargetInfo* createX86TargetInfo()
	{
		TargetInfo* targetInfo = createTargetInfoPass();
		x86TargetInfo(targetInfo);
		return targetInfo;
	}
	
	ErrorOr<unique_ptr<Module>> makeModule(LLVMContext& context, Executable& object, const string& objectName)
	{
		x86_config config64 = { 8, X86_REG_RIP, X86_REG_RSP, X86_REG_RBP };
		translation_context transl(context, config64, objectName);
		unordered_map<uint64_t, SymbolInfo> toVisit;
		
		for (uint64_t address : object.getVisibleEntryPoints())
		{
			auto symbolInfo = object.getInfo(address);
			assert(symbolInfo != nullptr);
			if (symbolInfo->name != "")
			{
				transl.create_alias(symbolInfo->virtualAddress, symbolInfo->name);
			}
			toVisit.insert({symbolInfo->virtualAddress, *symbolInfo});
		}
		
		for (uint64_t address : additionalEntryPoints)
		{
			if (auto symbolInfo = object.getInfo(address))
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
			
			result_function fn_temp = transl.create_function(functionInfo.name, functionInfo.virtualAddress, functionInfo.memory, object.end());
			auto inserted_function = functions.insert(make_pair(functionInfo.virtualAddress, move(fn_temp))).first;
			result_function& fn = inserted_function->second;
			
			for (auto callee = fn.callees_begin(); callee != fn.callees_end(); callee++)
			{
				auto destination = *callee;
				if (functions.find(destination) == functions.end())
				if (auto symbolInfo = object.getInfo(destination))
				{
					toVisit.insert({destination, *symbolInfo});
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
		return move(module);
	}
	
	void annotateStubs(Module& module, Executable& object)
	{
		LLVMContext& ctx = module.getContext();
		Function* jumpIntrin = module.getFunction("x86_jump_intrin");
		
		// This may eventually need to be moved to a pass of its own or something.
		vector<Function*> functions;
		for (Function& fn : module.getFunctionList())
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
						if (const string* stubTarget = object.getStubTarget(intValue))
						{
							MDNode* nameNode = MDNode::get(ctx, MDString::get(ctx, *stubTarget));
							fn.setMetadata("fcd.importname", nameNode);
						}
					}
				}
			}
		}
	}
	
	int decompile(Module& module, raw_os_ostream& output)
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
			return 1;
		}
		
		// Phase two: discover things, simplify other things
		RegisterUse registerUse;
		for (int i = 0; i < 2; i++)
		{
			auto phaseTwo = createBasePassManager();
			phaseTwo.add(createX86TargetInfo());
			phaseTwo.add(new RegisterUseWrapper(registerUse));
			phaseTwo.add(createLibraryRegisterUsePass());
			phaseTwo.add(createIpaRegisterUsePass());
			phaseTwo.add(createGVNPass());
			phaseTwo.add(createDeadStoreEliminationPass());
			phaseTwo.add(createInstructionCombiningPass());
			phaseTwo.add(createCFGSimplificationPass());
			phaseTwo.run(module);
			
#if DEBUG
			if (verifyModule(module, &output))
			{
				// errors!
				return 1;
			}
#endif
		}
		
		// Phase 3: make into functions with arguments, run codegen
		auto phaseThree = createBasePassManager();
		phaseThree.add(createX86TargetInfo());
		phaseThree.add(new RegisterUseWrapper(registerUse));
		phaseThree.add(createArgumentRecoveryPass());
		phaseThree.add(createSignExtPass());
		phaseThree.add(createInstructionCombiningPass());
		phaseThree.add(createSROAPass());
		phaseThree.add(createGVNPass());
		phaseThree.add(createDeadStoreEliminationPass());
		phaseThree.add(createIPSCCPPass());
		phaseThree.add(createCFGSimplificationPass());
		phaseThree.add(createGlobalDCEPass());
		phaseThree.run(module);
		
#ifdef DEBUG
		if (verifyModule(module, &output))
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
		outputPhase.run(module);
		
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
		
		// XXX: remove when MemorySSA goes mainstream
		initializeMemorySSAPrinterPassPass(pr);
		initializeMemorySSALazyPass(pr);
		
		initializeIpaRegisterUsePass(pr);
		initializeTargetInfoPass(pr);
		initializeRegisterUseWrapperPass(pr);
		initializeArgumentRecoveryPass(pr);
		initializeAstBackEndPass(pr);
		initializeSESELoopPass(pr);
	}
}

int main(int argc, char** argv)
{
	using sys::path::filename;
	
	pruneOptionList(cl::getRegisteredOptions());
	cl::ParseCommandLineOptions(argc, argv, "native program decompiler");
	
	auto programName = filename(argv[0]).str();
	
	if (auto bufferOrError = MemoryBuffer::getFile(inputFile, -1, false))
	{
		initializePasses();
		
		unique_ptr<MemoryBuffer>& buffer = bufferOrError.get();
		auto start = reinterpret_cast<const uint8_t*>(buffer->getBufferStart());
		auto end = reinterpret_cast<const uint8_t*>(buffer->getBufferEnd());
		if (auto executableOrError = Executable::parse(start, end))
		{
			unique_ptr<Executable>& executable = executableOrError.get();
			LLVMContext& context = getGlobalContext();
			if (auto moduleOrError = makeModule(context, *executable, filename(inputFile)))
			{
				auto& module = moduleOrError.get();
				raw_os_ostream rout(cout);
				annotateStubs(*module, *executable);
				decompile(*module, rout);
				return 0;
			}
			else
			{
				cerr << programName << ": couldn't build LLVM module out of " << inputFile << ": " << errorOf(moduleOrError) << endl;
				return 1;
			}
		}
		else
		{
			cerr << programName << ": couldn't parse " << inputFile << ": " << errorOf(executableOrError) << endl;
			return 1;
		}
	}
	else
	{
		cerr << programName << ": can't open " << inputFile << ": " << errorOf(bufferOrError) << endl;
		return 1;
	}
}
