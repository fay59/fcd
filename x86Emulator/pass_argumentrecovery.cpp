//
//  pass_ArgumentRecovery.cpp
//  x86Emulator
//
//  Created by Félix on 2015-05-01.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <iostream>
#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/RegionPass.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <string>
#include <unordered_map>
#include <vector>

#include "passes.h"
#include "x86_register_map.h"

using namespace llvm;
using namespace std;

namespace
{
	struct ParameterUseInfo
	{
		enum {
			IsRead = 1,
			IsWritten = 2,
		};
		
		Instruction* dominating;
		unsigned type;
		
		ParameterUseInfo()
		{
			dominating = nullptr;
			type = 0;
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
			au.setPreservesAll();
		}
		
		virtual bool runOnSCC(CallGraphSCC& scc) override
		{
			for (CallGraphNode* cgn : scc)
			{
				runOnCallGraphNode(cgn);
			}
			return false;
		}
		
		void runOnCallGraphNode(CallGraphNode* cgn)
		{
			Function* fn = cgn->getFunction();
			if (fn == nullptr || fn->isDeclaration())
			{
				return;
			}
			
			dom.recalculate(*fn);
			
			Argument* regs = fn->arg_begin();
			// assume x86 regs as first parameter
			assert(cast<PointerType>(regs->getType())->getTypeAtIndex(unsigned(0))->getStructName() == "struct.x86_regs");
			
			// get GEP uses of regs (find set of registers used)
			unordered_map<string, ParameterUseInfo> useSet;
			for (User* user : regs->users())
			{
				if (auto gep = dyn_cast<GetElementPtrInst>(user))
				{
					APInt offset(64, 0, false);
					if (gep->accumulateConstantOffset(*layout, offset))
					{
						constexpr size_t size = 8;
						size_t registerOffset = offset.getLimitedValue() & ~(size-1);
						string name = x86_get_register_name(registerOffset, size);
						
						ParameterUseInfo info = processPointerUse(dom, gep);
						auto iter = useSet.find(name);
						if (iter == useSet.end())
						{
							useSet.insert(make_pair(name, info));
						}
						else
						{
							dominator(dom, info.dominating, iter->second);
						}
					}
					else
					{
						assert(!"non-constant GEP on registers");
					}
				}
			}
			
			cout << fn->getName().str() << ":\n";
			for (auto& pair : useSet)
			{
				cout << pair.first << ": ";
				if (dyn_cast<LoadInst>(pair.second.dominating))
				{
					cout << "Used";
				}
				else
				{
					cout << "Scrapped";
				}
				cout << '\n';
			}
			cout << endl;
		}
		
		ParameterUseInfo processPointerUse(DominatorTree& dom, Instruction* pointerInst)
		{
			// At this stage, we don't care yet about whether a value is preserved or not.
			// We just want to find out if the register is read before being written to.
			ParameterUseInfo info;
			for (User* user : pointerInst->users())
			{
				if (CastInst* cast = dyn_cast<CastInst>(user))
				{
					auto userInfo = processPointerUse(dom, cast);
					info.type |= userInfo.type;
					user = userInfo.dominating;
				}
				dominator(dom, user, info);
			}
			return info;
		}
		
		void dominator(DominatorTree& dom, User* contender, ParameterUseInfo& useInfo)
		{
			Instruction* current = useInfo.dominating;
			if (LoadInst* load = dyn_cast<LoadInst>(contender))
			{
				useInfo.type = ParameterUseInfo::IsRead;
				if (current == nullptr)
				{
					useInfo.dominating = load;
				}
				else if (dom.dominates(load, current) || !dom.dominates(current, load))
				{
					// if neither instruction dominates the other, then there is a branch where
					// the value is loaded without there being a chance that it has been written to.
					useInfo.dominating = load;
				}
			}
			else if (StoreInst* store = dyn_cast<StoreInst>(contender))
			{
				useInfo.type = ParameterUseInfo::IsWritten;
				if (current == nullptr || dom.dominates(store, current))
				{
					useInfo.dominating = store;
				}
			}
		}
	};
	
	char ArgumentRecovery::ID = 0;
	static RegisterPass<ArgumentRecovery> argrec("argrec", "Recover arguments from function", true, true);
}

CallGraphSCCPass* createArgumentRecoveryPass()
{
	return new ArgumentRecovery;
}

