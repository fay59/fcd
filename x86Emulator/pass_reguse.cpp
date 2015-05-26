//
//  pass_ArgumentRecovery.cpp
//  x86Emulator
//
//  Created by Félix on 2015-05-01.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <iostream>
#include <llvm/ADT/SCCIterator.h>
#include <llvm/Analysis/MemoryDependenceAnalysis.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/RegionPass.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Transforms/Utils/MemorySSA.h>
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
	struct ValueRelevance
	{
		enum {
			// uses live-on-entry definition
			UsesDefinition = 1,
			
			// kills definition
			KillsDefinition = 2,
			
			// register is used (safeguard against zero-init)
			RegisterUsed = 4,
		};
	};
	
	string useTypeAsString(unsigned a)
	{
		string result;
		raw_string_ostream ss(result);
		ss << '(';
		if (a & ValueRelevance::RegisterUsed)
		{
			if (a & ValueRelevance::UsesDefinition)
			{
				ss << "uses-def";
				if (a & ValueRelevance::KillsDefinition)
				{
					ss << ", ";
				}
			}
			if (a & ValueRelevance::KillsDefinition)
			{
				ss << "kills-def";
			}
		}
		ss << ')';
		ss.flush();
		return result;
	}
	
	struct RegisterUse : public ModulePass, public AliasAnalysis
	{
		static char ID;
		
		unordered_map<const Function*, unordered_map<const char*, unsigned>> registerUse;
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
				if (regIter != iter->second.end() && (regIter->second & ValueRelevance::RegisterUsed))
				{
					unsigned modRef = 0;
					if (regIter->second & ValueRelevance::KillsDefinition)
					{
						modRef |= Mod;
					}
					if (regIter->second & ValueRelevance::UsesDefinition)
					{
						modRef |= Ref;
					}
					return static_cast<ModRefResult>(modRef);
				}
			}
			
			// no idea
			return AliasAnalysis::getModRefInfo(cs, location);
		}
		
		virtual bool runOnModule(Module& m) override
		{
			layout = &m.getDataLayout();
			InitializeAliasAnalysis(this, layout);
			
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
				for (User* u : iter->second->users())
				{
					gepUsers[iter->first].insert(cast<Instruction>(u));
				}
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
			
			/*
			// Now find which memory operations load instructions depend on.
			raw_os_ostream rout(cout);
			MemorySSA mssa(*fn);
			mssa.buildMemorySSA(&getAnalysis<AliasAnalysis>(), &getAnalysis<DominatorTreeWrapperPass>(*fn).getDomTree());
			mssa.print(rout);
			for (auto iter = gepUsers.begin(); iter != gepUsers.end(); iter++)
			{
				auto& set = iter->second;
				for (Instruction* i : set)
				{
					if (auto load = dyn_cast<LoadInst>(i))
					{
						load->dump();
						MemoryAccess* loadAccess = mssa.getMemoryAccess(load);
						MemoryAccess* access = loadAccess->getDefiningAccess();
						Instruction* cause = access ? access->getMemoryInst() : nullptr;
						while (auto call = dyn_cast_or_null<CallInst>(cause))
						{
							const char* registerName = registerNameForPointerOperand(*load->getPointerOperand());
							if (!callPreservesRegister(*call->getCalledFunction(), registerName))
							{
								goto endTestPreservation;
							}
							call->dump();
							
							access = access->getDefiningAccess();
							cause = access ? access->getMemoryInst() : nullptr;
						}
						
						// Every call in the sequence preserves the register. This load is unnecessary.
						// Walk to the last aliasing definition.
						
						// !!!
						// Turn this into a ModRef alias analysis pass.
						
					endTestPreservation:
						puts("");
					}
				}
			}
			 */
			
			cout << fn->getName().str() << ":" << endl;
			for (auto& pair : dominantUses)
			{
				cout << pair.first << '\n';
				for (auto inst : pair.second)
				{
					inst->dump();
				}
				cout << endl;
			}
			
			for (auto& pair : dominantUses)
			{
				cout << pair.first << ": ";
				unsigned type = ValueRelevance::UsesDefinition;
				for (auto inst : pair.second)
				{
					if (isa<StoreInst>(inst) || isa<CallInst>(inst))
					{
						// As soon as you find a dominant store, the register is defined.
						type = ValueRelevance::KillsDefinition;
						break;
					}
					else if (!isa<LoadInst>(inst))
					{
						assert(!"Unknown inst type");
					}
				}
				cout << useTypeAsString(type | ValueRelevance::RegisterUsed) << endl;
			}
			cout << endl;
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
			
			// this will zero-fill missing entries, which is ok as it means "unused"
			unsigned value = registerMap[registerName];
			return (value & ValueRelevance::RegisterUsed) == ValueRelevance::RegisterUsed
				? (value & ValueRelevance::KillsDefinition) == 0
				: false;
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
	};
	
	char RegisterUse::ID = 0;
}

INITIALIZE_PASS_BEGIN(RegisterUse, "reguse", "ModRef info for registers", true, true)
INITIALIZE_AG_DEPENDENCY(AliasAnalysis)
INITIALIZE_PASS_DEPENDENCY(CallGraphWrapperPass)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(MemorySSALazy)
INITIALIZE_PASS_END(RegisterUse, "reguse", "ModRef info for registers", true, true)

ModulePass* createRegisterUsePass()
{
	return new RegisterUse;
}

