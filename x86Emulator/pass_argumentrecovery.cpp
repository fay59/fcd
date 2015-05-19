//
//  pass_ArgumentRecovery.cpp
//  x86Emulator
//
//  Created by Félix on 2015-05-01.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <iostream>
#include <llvm/Analysis/MemoryDependenceAnalysis.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/RegionPass.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "passes.h"
#include "x86_register_map.h"

using namespace llvm;
using namespace std;

namespace
{
	enum class RegisterUseType : unsigned
	{
		Unused,
		Used,
		Defined,
	};
	
	string useTypeAsString(RegisterUseType a)
	{
		switch (a)
		{
			case RegisterUseType::Unused: return "unused";
			case RegisterUseType::Used: return "used";
			case RegisterUseType::Defined: return "defined";
		}
	}
	
	struct ParameterUseInfo
	{
		Instruction* dominating;
		RegisterUseType type;
		
		ParameterUseInfo()
		{
			dominating = nullptr;
			type = RegisterUseType::Unused;
		}
		
		bool isUsedFirst() const
		{
			return dyn_cast<LoadInst>(dominating) != nullptr;
		}
		
		bool isDefinedFirst() const
		{
			return dyn_cast<StoreInst>(dominating) != nullptr;
		}
	};
	
	struct ArgumentRecovery : public CallGraphSCCPass
	{
		static char ID;
		
		unordered_map<Function*, unordered_map<string, RegisterUseType>> registerUse;
		const DataLayout* layout;
		DominatorTree dom;
		
		ArgumentRecovery() : CallGraphSCCPass(ID)
		{
		}
		
		virtual const char* getPassName() const override
		{
			return "Argument Recovery";
		}
		
		virtual bool doInitialization(CallGraph& cg) override
		{
			layout = &cg.getModule().getDataLayout();
			return false;
		}
		
		virtual void getAnalysisUsage(AnalysisUsage& au) const override
		{
			//au.addRequired<DominatorTree>();
			//au.addRequired<MemoryDependenceAnalysis>();
			au.setPreservesAll();
		}
		
		virtual bool runOnSCC(CallGraphSCC& scc) override
		{
			for (CallGraphNode* cgn : scc)
			{
				Function* fn = cgn->getFunction();
				if (fn == nullptr || fn->isDeclaration())
				{
					continue;
				}
				
				dom.recalculate(*fn);
				runOnFunction(fn);
			}
			return false;
		}
		
		void runOnFunction(Function* fn)
		{
			Argument* regs = fn->arg_begin();
			// assume x86 regs as first parameter
			assert(cast<PointerType>(regs->getType())->getTypeAtIndex(unsigned(0))->getStructName() == "struct.x86_regs");
			
			// Find all GEPs
			unordered_map<string, ParameterUseInfo> useSet;
			unordered_multimap<const char*, User*> registerUsers;
			for (User* user : regs->users())
			{
				if (auto gep = dyn_cast<GetElementPtrInst>(user))
				{
					APInt offset(64, 0, false);
					if (gep->accumulateConstantOffset(*layout, offset))
					{
						constexpr size_t size = 8;
						size_t registerOffset = offset.getLimitedValue() & ~(size-1);
						const char* name = x86_get_register_name(registerOffset, size);
						registerUsers.insert(make_pair(name, gep));
					}
					else
					{
						assert(!"non-constant GEP on registers");
					}
				}
			}
			
			// Find all users of these GEP
			unordered_map<const char*, unordered_set<Instruction*>> gepUsers;
			for (auto iter = registerUsers.begin(); iter != registerUsers.end(); iter++)
			{
				for (User* u : iter->second->users())
				{
					if (auto castInst = dyn_cast<CastInst>(u))
					{
						assert(castInst->getDestTy()->isPointerTy());
						registerUsers.insert(make_pair(iter->first, castInst));
					}
					else
					{
						gepUsers[iter->first].insert(cast<Instruction>(u));
					}
				}
			}
			
			// Find the dominant use(s)
			for (auto iter = gepUsers.begin(); iter != gepUsers.end(); iter++)
			{
				auto& set = iter->second;
				auto setIter = set.begin();
				while (setIter != set.end())
				{
					auto testIter = set.begin();
					while (testIter != set.end())
					{
						if (testIter == setIter)
						{
							testIter++;
							continue;
						}
						
						if (dom.dominates(*setIter, *testIter))
						{
							testIter = set.erase(testIter);
						}
						else
						{
							testIter++;
						}
					}
					setIter++;
				}
			}
			
			cout << fn->getName().str() << ":" << endl;
			for (auto& pair : gepUsers)
			{
				cout << pair.first << ": ";
				auto type = RegisterUseType::Used;
				for (auto inst : pair.second)
				{
					if (isa<StoreInst>(inst) || isa<CallInst>(inst))
					{
						// As soon as you find a dominant store, the register is defined.
						type = RegisterUseType::Defined;
						break;
					}
					else if (!isa<LoadInst>(inst))
					{
						assert(!"Unknown inst type");
					}
				}
				cout << useTypeAsString(type) << endl;
			}
			cout << endl;
		}
	};
	
	char ArgumentRecovery::ID = 0;
	static RegisterPass<ArgumentRecovery> argrec("argrec", "Recover arguments from function", true, true);
}

CallGraphSCCPass* createArgumentRecoveryPass()
{
	return new ArgumentRecovery;
}

