//
//  main.cpp
//  x86Emulator
//
//  Created by Félix on 2015-04-17.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <fcntl.h>
#include <iostream>
#include <llvm/Analysis/Passes.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/Scalar.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <sys/mman.h>

#include "passes.h"
#include "capstone_wrapper.h"
#include "translation_context.h"

using namespace llvm;
using namespace std;

namespace
{
	int compile(uint64_t baseAddress, uint64_t offsetAddress, const uint8_t* begin, const uint8_t* end)
	{
		size_t dataSize = end - begin;
		LLVMContext context;
		//x86_config config32 = { 4, X86_REG_EIP, X86_REG_ESP, X86_REG_EBP };
		x86_config config64 = { 8, X86_REG_RIP, X86_REG_RSP, X86_REG_RBP };
		translation_context transl(context, config64, "shiny");
		
		unordered_set<uint64_t> toVisit { offsetAddress };
		unordered_map<uint64_t, result_function> functions;
		while (toVisit.size() > 0)
		{
			auto iter = toVisit.begin();
			uint64_t base = *iter;
			toVisit.erase(iter);
			
			string name = "x86_";
			raw_string_ostream(name).write_hex(base);
			
			result_function fn_temp = transl.create_function(name, base, begin + (base - baseAddress), end);
			auto inserted_function = functions.insert(make_pair(base, move(fn_temp))).first;
			result_function& fn = inserted_function->second;
			
			for (auto callee = fn.callees_begin(); callee != fn.callees_end(); callee++)
			{
				auto destination = *callee;
				auto functionIter = functions.find(destination);
				if (functionIter == functions.end() && destination >= baseAddress && destination < baseAddress + dataSize)
				{
					toVisit.insert(destination);
				}
			}
		}
		
		auto module = transl.take();
		for (auto& pair : functions)
		{
			pair.second.take();
		}
		
		// Optimize result
		raw_os_ostream rout(cout);
		legacy::PassManager phaseOne;
		
		// Phase one: optimize into relatively concise form, suitable for easy analysis
		phaseOne.add(createTypeBasedAliasAnalysisPass());
		phaseOne.add(createScopedNoAliasAAPass());
		phaseOne.add(createBasicAliasAnalysisPass());
		phaseOne.add(createAddressSpaceAliasAnalysisPass());
		phaseOne.add(createInstructionCombiningPass());
		phaseOne.add(createCFGSimplificationPass());
		phaseOne.add(createNewGVNPass());
		phaseOne.add(createDeadStoreEliminationPass());
		phaseOne.add(createInstructionCombiningPass());
		phaseOne.add(createCFGSimplificationPass());
		phaseOne.add(createGlobalDCEPass());
		phaseOne.run(*module);
		
		legacy::PassManager phaseTwo;
		phaseTwo.add(createTypeBasedAliasAnalysisPass());
		phaseTwo.add(createScopedNoAliasAAPass());
		phaseTwo.add(createBasicAliasAnalysisPass());
		phaseTwo.add(createAddressSpaceAliasAnalysisPass());
		phaseTwo.add(createRegisterUsePass());
		phaseTwo.add(createNewGVNPass());
		phaseTwo.run(*module);
		
		module->print(rout, nullptr);
		
		return 0;
	}
}

int main(int argc, const char** argv)
{
	if (argc != 2)
	{
		fprintf(stderr, "gimme a path you twat\n");
		return 1;
	}
	
	int file = open(argv[1], O_RDONLY);
	if (file == -1)
	{
		perror("open");
		return 1;
	}
	
	ssize_t size = lseek(file, 0, SEEK_END);
	
	void* data = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, file, 0);
	close(file);
	if (data == MAP_FAILED)
	{
		perror("mmap");
	}
	
	initializeRegisterUsePass(*PassRegistry::getPassRegistry());
	
	const uint8_t* begin = static_cast<const uint8_t*>(data);
	return compile(0x100000000, 0x100000f20, begin, begin + size);
}
