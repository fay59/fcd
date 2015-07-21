//
//  main.cpp
//  x86Emulator
//
//  Created by Félix on 2015-04-17.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Analysis/Passes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/Scalar.h>
SILENCE_LLVM_WARNINGS_END()

#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <sys/mman.h>

#include "passes.h"
#include "capstone_wrapper.h"
#include "translation_context.h"
#include "x86_register_map.h"

using namespace llvm;
using namespace llvm::object;
using namespace std;

namespace
{
	struct erase_inst
	{
		Instruction* inst;
		erase_inst(Instruction* inst) : inst(inst)
		{
		}
		~erase_inst()
		{
			delete inst;
		}
	};
	
	template<typename TAction>
	size_t forEachCall(Function* callee, unsigned stringArgumentIndex, TAction&& action)
	{
		size_t count = 0;
		for (Use& use : callee->uses())
		{
			if (auto call = dyn_cast<CallInst>(use.getUser()))
			{
				unique_ptr<erase_inst> eraseIfNecessary;
				Value* operand = call->getOperand(stringArgumentIndex);
				if (auto constant = dyn_cast<ConstantExpr>(operand))
				{
					eraseIfNecessary.reset(new erase_inst(constant->getAsInstruction()));
					operand = eraseIfNecessary->inst;
				}
				
				if (auto gep = dyn_cast<GetElementPtrInst>(operand))
				{
					if (auto global = dyn_cast<GlobalVariable>(gep->getOperand(0)))
					{
						if (auto dataArray = dyn_cast<ConstantDataArray>(global->getInitializer()))
						{
							action(dataArray->getAsString().str());
							count++;
						}
					}
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
	
	struct SymbolInfo
	{
		string name;
		uint64_t virtualAddress;
		const uint8_t* baseAddress;
		const uint8_t* upperBound;
	};
	
	unique_ptr<SymbolInfo> getSymbolInfo(ObjectFile& object, SymbolRef& symbol)
	{
		StringRef name;
		uint64_t address;
		SymbolRef::Type type;
		auto sectionsEnd = object.section_end();
		section_iterator section = sectionsEnd;
		if (symbol.getName(name)) return nullptr;
		if (symbol.getAddress(address)) return nullptr;
		if (symbol.getType(type)) return nullptr;
		if (symbol.getSection(section)) return nullptr;
		
		if (type == SymbolRef::ST_Function && section != sectionsEnd)
		{
			StringRef sectionContents;
			uint64_t sectionAddress = section->getAddress();
			if (section->getContents(sectionContents)) return nullptr;
			
			auto offset = address - sectionAddress;
			if (offset < sectionContents.size())
			{
				unique_ptr<SymbolInfo> result(new SymbolInfo);
				result->name = name.str();
				result->virtualAddress = address;
				result->baseAddress = sectionContents.bytes_begin() + offset;
				result->upperBound = sectionContents.bytes_end();
				return result;
			}
		}
		return nullptr;
	}
	
	unique_ptr<SymbolInfo> getSymbolInfo(ObjectFile& object, uint64_t virtualAddress)
	{
		for (auto iter = object.section_begin(); iter != object.section_end(); ++iter)
		{
			uint64_t min = iter->getAddress();
			uint64_t max = min + iter->getSize();
			if (virtualAddress >= min && virtualAddress < max)
			{
				StringRef contents;
				if (iter->getContents(contents)) break;
				
				size_t offset = virtualAddress - min;
				unique_ptr<SymbolInfo> result(new SymbolInfo);
				(raw_string_ostream(result->name) << "func_").write_hex(virtualAddress);
				result->virtualAddress = virtualAddress;
				result->baseAddress = contents.bytes_begin() + offset;
				result->upperBound = contents.bytes_end();
				return result;
			}
		}
		return nullptr;
	}
	
	unique_ptr<Module> makeModule(LLVMContext& context, ObjectFile& object, const string& objectName)
	{
		x86_config config64 = { 8, X86_REG_RIP, X86_REG_RSP, X86_REG_RBP };
		translation_context transl(context, config64, objectName);
		unordered_map<uint64_t, SymbolInfo> toVisit;
		
		for (auto symbol : object.symbols())
		{
			if (auto symbolInfo = getSymbolInfo(object, symbol))
			{
				transl.create_alias(symbolInfo->virtualAddress, symbolInfo->name);
				toVisit.insert({symbolInfo->virtualAddress, move(*symbolInfo)});
			}
		}
		
		unordered_map<uint64_t, result_function> functions;
		
		while (toVisit.size() > 0)
		{
			auto iter = toVisit.begin();
			auto functionInfo = iter->second;
			toVisit.erase(iter);
			
			result_function fn_temp = transl.create_function(functionInfo.name, functionInfo.virtualAddress, functionInfo.baseAddress, functionInfo.upperBound);
			auto inserted_function = functions.insert(make_pair(functionInfo.virtualAddress, move(fn_temp))).first;
			result_function& fn = inserted_function->second;
			
			for (auto callee = fn.callees_begin(); callee != fn.callees_end(); callee++)
			{
				auto destination = *callee;
				if (functions.find(destination) == functions.end())
				{
					if (auto symbolInfo = getSymbolInfo(object, destination))
					{
						toVisit.insert({destination, move(*symbolInfo)});
					}
				}
			}
		}
		
		// uint64_t baseAddress, uint64_t offsetAddress, const uint8_t* begin, const uint8_t* end
		for (auto& pair : functions)
		{
			pair.second.take();
		}
		
		return transl.take();
	}
	
	int decompile(Module& module, raw_os_ostream& output)
	{
		// Optimize result
		raw_os_ostream rout(cout);
		
		// Phase one: optimize into relatively concise form, suitable for easy analysis
		legacy::PassManager phaseOne = createBasePassManager();
		phaseOne.add(createInstructionCombiningPass());
		phaseOne.add(createCFGSimplificationPass());
		phaseOne.add(createRegisterPointerPromotionPass());
		phaseOne.add(createNewGVNPass());
		phaseOne.add(createDeadStoreEliminationPass());
		phaseOne.add(createInstructionCombiningPass());
		phaseOne.add(createCFGSimplificationPass());
		phaseOne.add(createGlobalDCEPass());
		phaseOne.run(module);
		
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
		for (int i = 0; i < 2; i++)
		{
			auto phaseTwo = createBasePassManager();
			phaseTwo.add(createX86TargetInfo());
			phaseTwo.add(createRegisterUsePass());
			phaseTwo.add(createNewGVNPass());
			phaseTwo.add(createDeadStoreEliminationPass());
			phaseTwo.add(createInstructionCombiningPass());
			phaseTwo.add(createCFGSimplificationPass());
			phaseTwo.add(createNewGVNPass());
			phaseTwo.run(module);
		}
		
		// Phase 3: make into functions with arguments, run codegen
		auto phaseThree = createBasePassManager();
		phaseThree.add(createX86TargetInfo());
		phaseThree.add(createRegisterUsePass());
		phaseThree.add(createArgumentRecoveryPass());
		phaseThree.add(createInstructionCombiningPass());
		phaseThree.add(createSROAPass());
		phaseThree.add(createNewGVNPass());
		phaseThree.add(createDeadStoreEliminationPass());
		phaseThree.add(createGlobalDCEPass());
		phaseThree.run(module);
		
		if (verifyModule(module, &rout))
		{
			// errors!
			return 1;
		}
		
		// Run that module through the output pass
		unique_ptr<AstBackEnd> backend(createAstBackEnd());
		legacy::PassManager outputPhase;
		outputPhase.add(createX86TargetInfo());
		outputPhase.add(createSESELoopPass());
		outputPhase.add(backend.get());
		outputPhase.run(module);
		
		for (auto& pair : move(*backend).getResult())
		{
			output << pair.second << '\n';
		}
		
		return 0;
	}
	
	const char* basename(const char* path)
	{
		const char* result = path;
		for (auto iter = result; *iter; iter++)
		{
			if (*iter == '/')
			{
				result = iter + 1;
			}
		}
		return result;
	}
}

int main(int argc, const char** argv)
{
	const char* programName = basename(argv[0]);
	
	if (argc != 2)
	{
		cerr << "usage: " << argv[0] << " path" << endl;
		return 1;
	}
	
	const char* fileName = basename(argv[1]);
	int file = open(argv[1], O_RDONLY);
	if (file == -1)
	{
		perror("open");
		return 2;
	}
	
	ssize_t size = lseek(file, 0, SEEK_END);
	
	const void* data = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, file, 0);
	close(file);
	if (data == MAP_FAILED)
	{
		perror("mmap");
		return 2;
	}
	
	auto& pr = *PassRegistry::getPassRegistry();
	initializeCore(pr);
	initializeScalarOpts(pr);
	initializeVectorization(pr);
	initializeIPO(pr);
	initializeAnalysis(pr);
	initializeIPA(pr);
	initializeTransformUtils(pr);
	initializeInstCombine(pr);
	
	initializeTargetInfoPass(pr);
	initializeRegisterUsePass(pr);
	initializeArgumentRecoveryPass(pr);
	initializeAstBackEndPass(pr);
	initializeSESELoopPass(pr);
	
	StringRef dataAsStringRef(static_cast<const char*>(data), size);
	MemoryBufferRef dataAsMemoryBuffer(dataAsStringRef, "Executable Data");
	auto objectOrError = ObjectFile::createObjectFile(dataAsMemoryBuffer);
	if (auto error = objectOrError.getError())
	{
		cerr << programName << ": can't open " << argv[1] << " as a binary: " << error.message() << endl;
		return 2;
	}
	
	unordered_map<const uint8_t*, string> symbols;
	unique_ptr<ObjectFile> object = move(objectOrError.get());
	
	LLVMContext context;
	if (auto module = makeModule(context, *object, fileName))
	{
		raw_os_ostream rout(cout);
		decompile(*module, rout);
	}
}
