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
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <sys/mman.h>

#include "asaa.h"
#include "capstone_wrapper.h"
#include "translation_context.h"

using namespace llvm;
using namespace std;

namespace
{
	void addAddressSpaceAA(const PassManagerBuilder& builder, legacy::PassManagerBase& pm)
	{
		pm.add(createAddressSpaceAliasAnalysisPass());
	}
	
	int compile(uint64_t baseAddress, uint64_t offsetAddress, const uint8_t* begin, const uint8_t* end)
	{
		size_t dataSize = end - begin;
		LLVMContext context;
		x86_config config = { 32, X86_REG_EIP, X86_REG_ESP, X86_REG_EBP };
		translation_context transl(context, config, "shiny");
		
		unordered_set<uint64_t> toVisit { offsetAddress };
		unordered_map<uint64_t, Function*> functions;
		while (toVisit.size() > 0)
		{
			auto iter = toVisit.begin();
			uint64_t base = *iter;
			toVisit.erase(iter);
			
			string name = "x86_";
			raw_string_ostream(name).write_hex(base);
			
			result_function fn = transl.create_function(name, base, begin + (base - baseAddress), end);
			for (auto iter = fn.intrin_begin(); iter != fn.intrin_end(); iter++)
			{
				auto call = cast<CallInst>((*iter)->begin());
				auto name = call->getCalledValue()->getName();
				if (name == "x86_call_intrin")
				{
					auto destination = call->getOperand(2);
					if (auto constant = dyn_cast<ConstantInt>(destination))
					{
						uint64_t address = constant->getLimitedValue();
						auto functionIter = functions.find(address);
						if (functionIter == functions.end() && address >= baseAddress && address < baseAddress + dataSize)
						{
							toVisit.insert(address);
						}
					}
				}
			}
			
			functions.insert(make_pair(base, fn.take()));
		}
		
		auto module = transl.take();
		
		// (actually) optimize result
		legacy::PassManager pm;
		
		PassManagerBuilder pmb;
		pmb.addExtension(PassManagerBuilder::EP_ModuleOptimizerEarly, &addAddressSpaceAA);
		pmb.populateModulePassManager(pm);
		pm.run(*module);
		
		raw_os_ostream rout(cout);
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
	
	const uint8_t* begin = static_cast<const uint8_t*>(data);
	return compile(0x8048000, 0x80484a0, begin, begin + size);
}
