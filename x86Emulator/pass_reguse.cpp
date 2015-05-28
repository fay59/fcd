//
//  pass_ArgumentRecovery.cpp
//  x86Emulator
//
//  Created by Félix on 2015-05-01.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include "llvm_warnings.h"

#include <iostream>

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/SCCIterator.h>
#include <llvm/Analysis/MemoryDependenceAnalysis.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/Analysis/RegionPass.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Transforms/Utils/MemorySSA.h>
SILENCE_LLVM_WARNINGS_END()

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
	bool postDominates(PostDominatorTree& dom, Instruction* a, Instruction* b)
	{
		if (a == b)
		{
			return false;
		}
		
		BasicBlock* aBlock = a->getParent();
		BasicBlock* bBlock = b->getParent();
		if (aBlock == bBlock)
		{
			// which one happens last?
			for (auto iter = aBlock->begin(); iter != aBlock->end(); iter++)
			{
				if (&*iter == a)
				{
					return false;
				}
				if (&*iter == b)
				{
					return true;
				}
			}
			llvm_unreachable("neither A nor B present in parent block?!");
		}
		
		return dom.dominates(aBlock, bBlock);
	}
	
	struct RegisterUse : public ModulePass, public AliasAnalysis
	{
		static char ID;
		
		unordered_map<const Function*, unordered_map<const char*, ModRefResult>> registerUse;
		const DataLayout* layout;
		
		RegisterUse() : ModulePass(ID)
		{
		}
		
		virtual const char* getPassName() const override
		{
			return "Argument Recovery";
		}
		
		virtual void getAnalysisUsage(AnalysisUsage &au) const override
		{
			AliasAnalysis::getAnalysisUsage(au);
			au.addRequired<AliasAnalysis>();
			au.addRequired<CallGraphWrapperPass>();
			au.addRequired<DominatorTreeWrapperPass>();
			au.addRequired<PostDominatorTree>();
		}
		
		virtual void *getAdjustedAnalysisPointer(AnalysisID PI) override
		{
			if (PI == &AliasAnalysis::ID)
				return (AliasAnalysis*)this;
			return this;
		}
		
		virtual ModRefResult getModRefInfo(ImmutableCallSite& cs, const Location& location)
		{
			auto iter = registerUse.find(cast<CallInst>(cs.getInstruction())->getCalledFunction());
			if (iter != registerUse.end())
			{
				const char* registerName = registerNameForPointerOperand(*location.Ptr);
				auto regIter = iter->second.find(registerName);
				if (regIter != iter->second.end())
				{
					return regIter->second;
				}
			}
			
			// no idea
			return AliasAnalysis::getModRefInfo(cs, location);
		}
		
		virtual bool runOnModule(Module& m) override
		{
			layout = &m.getDataLayout();
			InitializeAliasAnalysis(this, layout);
			
			// HACKHACK: library data
			systemv_abi(m.getFunction("x86_100000f68"));
			systemv_abi(m.getFunction("x86_100000f6e"));
			
			CallGraph& cg = getAnalysis<CallGraphWrapperPass>().getCallGraph();
			
			scc_iterator<CallGraph*> cgSccIter = scc_begin(&cg);
			CallGraphSCC curSCC(&cgSccIter);
			while (!cgSccIter.isAtEnd())
			{
				const vector<CallGraphNode*>& nodeVec = *cgSccIter;
				curSCC.initialize(nodeVec.data(), nodeVec.data() + nodeVec.size());
				runOnSCC(curSCC);
				++cgSccIter;
			}
			
			return false;
		}
		
		bool runOnSCC(CallGraphSCC& scc)
		{
			for (CallGraphNode* cgn : scc)
			{
				Function* fn = cgn->getFunction();
				if (fn == nullptr || fn->isDeclaration())
				{
					continue;
				}
				
				runOnFunction(fn);
			}
			return false;
		}
		
		void runOnFunction(Function* fn)
		{
			// Recursive calls to this function are likely for non-singular SSCs.
			if (registerUse.find(fn) != registerUse.end())
			{
				return;
			}
			
			auto& resultMap = registerUse[fn];
			
			Argument* regs = fn->arg_begin();
			// assume x86 regs as first parameter
			assert(cast<PointerType>(regs->getType())->getTypeAtIndex(unsigned(0))->getStructName() == "struct.x86_regs");
			
			// Find all GEPs
			unordered_multimap<const char*, User*> registerUsers;
			for (User* user : regs->users())
			{
				if (const char* registerName = registerNameForPointerOperand(*user))
				{
					registerUsers.insert({registerName, user});
				}
			}
			
			// Find all users of these GEP
			unordered_map<const char*, unordered_set<Instruction*>> gepUsers;
			for (auto iter = registerUsers.begin(); iter != registerUsers.end(); iter++)
			{
				addAllUsers(*iter->second, iter->first, gepUsers);
			}
			
			// Find the dominant use(s)
			auto dominantUses = gepUsers;
			DominatorTree& dom = getAnalysis<DominatorTreeWrapperPass>(*fn).getDomTree();
			for (auto iter = dominantUses.begin(); iter != dominantUses.end(); iter++)
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
			
			// Fill out use dictionary
			for (auto& pair : dominantUses)
			{
				ModRefResult& r = resultMap[pair.first];
				r = Ref;
				for (auto inst : pair.second)
				{
					if (isa<StoreInst>(inst) || isa<CallInst>(inst))
					{
						// As soon as you find a dominant store, the register is defined.
						r = Mod;
						break;
					}
				}
			}
			
			// Find post-dominating uses
			auto dominatedUses = gepUsers;
			PostDominatorTree& postDom = getAnalysis<PostDominatorTree>(*fn);
			for (auto iter = dominatedUses.begin(); iter != dominatedUses.end(); iter++)
			{
				cout << iter->first << endl;
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
						
						if (postDominates(postDom, *setIter, *testIter))
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
			
			cout << fn->getName().str() << "\n";
			for (auto& pair : dominatedUses)
			{
				cout << pair.first << "\n";
				for (auto use : pair.second)
				{
					use->dump();
				}
				cout << "\n";
			}
			cout << "\n";
			
			// All the Ref'd registers may actually be ModRef. As a heuristic, temporarily, mark them ModRef.
			for (auto& pair : resultMap)
			{
				if (pair.second == Ref)
				{
					pair.second = ModRef;
				}
			}
		}
		
		void addAllUsers(User& i, const char* reg, unordered_map<const char*, unordered_set<Instruction*>>& allUsers)
		{
			for (User* u : i.users())
			{
				if (CastInst* bitcast = dyn_cast<CastInst>(u))
				{
					addAllUsers(*bitcast, reg, allUsers);
				}
				else
				{
					allUsers[reg].insert(cast<Instruction>(u));
				}
			}
		}
		
		bool callPreservesRegister(Function& function, const char* registerName)
		{
			// ensure data is present
			runOnFunction(&function);
			
			auto& registerMap = registerUse[&function];
			if (registerMap.size() == 0)
			{
				// We are currently analyzing this function.
				// If we assume that the call preserves the register, will the function
				// preserve the register? We need to answer on this basis.
				
			}
			
			auto iter = registerMap.find(registerName);
			if (iter != registerMap.end())
			{
				return (iter->second & Mod) == 0;
			}
			return false;
		}
		
		const char* registerNameForPointerOperand(const Value& pointer)
		{
			if (const CastInst* castInst = dyn_cast<CastInst>(&pointer))
			{
				if (auto gep = dyn_cast<GetElementPtrInst>(castInst->getOperand(0)))
				{
					return registerNameForGep(*gep);
				}
			}
			else if (auto gep = dyn_cast<GetElementPtrInst>(&pointer))
			{
				return registerNameForGep(*gep);
			}
			return nullptr;
		}
		
		const char* registerNameForGep(const GetElementPtrInst& gep)
		{
			APInt offset(64, 0, false);
			if (gep.accumulateConstantOffset(*layout, offset))
			{
				constexpr size_t size = 8;
				size_t registerOffset = offset.getLimitedValue() & ~(size-1);
				return x86_get_register_name(registerOffset, size);
			}
			else
			{
				assert(!"non-constant GEP on registers");
			}
		}
		
		// HACKHACK
		void systemv_abi(Function* fn)
		{
			auto& table = registerUse[fn];
			table[x86_unique_register_name("rax")] = Mod;
			table[x86_unique_register_name("rdi")] = ModRef;
			table[x86_unique_register_name("rsi")] = ModRef;
			table[x86_unique_register_name("rdx")] = ModRef;
			table[x86_unique_register_name("rcx")] = ModRef;
			table[x86_unique_register_name("r8")] = ModRef;
			table[x86_unique_register_name("r9")] = ModRef;
			table[x86_unique_register_name("r10")] = ModRef;
			table[x86_unique_register_name("r11")] = ModRef;
			table[x86_unique_register_name("rip")] = Ref;
			table[x86_unique_register_name("rsp")] = Ref;
			table[x86_unique_register_name("rbp")] = Ref;
		}
	};
	
	char RegisterUse::ID = 0;
}

INITIALIZE_PASS_BEGIN(RegisterUse, "reguse", "ModRef info for registers", true, true)
INITIALIZE_AG_DEPENDENCY(AliasAnalysis)
INITIALIZE_PASS_DEPENDENCY(CallGraphWrapperPass)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(MemorySSALazy)
INITIALIZE_PASS_DEPENDENCY(PostDominatorTree)
INITIALIZE_PASS_END(RegisterUse, "reguse", "ModRef info for registers", true, true)

ModulePass* createRegisterUsePass()
{
	return new RegisterUse;
}

