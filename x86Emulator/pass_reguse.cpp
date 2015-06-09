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
#include <llvm/IR/Constants.h>
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
#include "symbolic_expr.h"
#include "x86_register_map.h"

using namespace llvm;
using namespace std;

namespace
{
	template<typename T, size_t N>
	constexpr size_t countof(T (&)[N])
	{
		return N;
	}
	
	constexpr auto Incomplete = static_cast<AliasAnalysis::ModRefResult>(4);
	constexpr auto IncompleteRef = static_cast<AliasAnalysis::ModRefResult>(Incomplete | AliasAnalysis::Ref);
	
	const char* modRefAsString(AliasAnalysis::ModRefResult mrb)
	{
		static const char* const modRefStrings[] = {
			[AliasAnalysis::NoModRef] = "-",
			[AliasAnalysis::Mod] = "mod",
			[AliasAnalysis::Ref] = "ref",
			[AliasAnalysis::ModRef] = "modref",
			[IncompleteRef] = "(incomplete) ref",
		};
		return modRefStrings[mrb];
	}
	
	bool dominates(DominatorTree& dom, Instruction* a, Instruction* b)
	{
		return dom.dominates(a, b);
	}
	
	bool dominates(PostDominatorTree& dom, Instruction* a, Instruction* b)
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
	
	template<typename TCollection, typename TDomTree>
	TCollection findDominantValues(TDomTree& dom, TCollection& set)
	{
		TCollection result = set;
		auto setIter = result.begin();
		while (setIter != result.end())
		{
			auto testIter = result.begin();
			while (testIter != result.end())
			{
				if (testIter == setIter)
				{
					testIter++;
					continue;
				}
				
				if (dominates(dom, *setIter, *testIter))
				{
					testIter = result.erase(testIter);
				}
				else
				{
					testIter++;
				}
			}
			setIter++;
		}
		return result;
	}
	
	struct RegisterUse : public ModulePass, public AliasAnalysis
	{
		typedef unordered_map<const char*, unordered_set<Instruction*>> DominatorsPerRegister;
		
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
		
		virtual ModRefResult getModRefInfo(ImmutableCallSite cs, const Location& location) override
		{
			auto iter = registerUse.find(cast<CallInst>(cs.getInstruction())->getCalledFunction());
			// The data here is incomplete when used for recursive calls. Any register that isn't trivially declared
			// Mod is declared Ref only. This is on purpose, as it allows us to bypass recursive calls to determine
			// if, notwithstanding the call itself, the function can modify the queried register.
			if (iter != registerUse.end())
			{
				const char* registerName = registerNameForPointerOperand(*location.Ptr);
				auto regIter = iter->second.find(registerName);
				return regIter == iter->second.end() ? NoModRef : regIter->second;
			}
			
			// no idea
			return AliasAnalysis::getModRefInfo(cs, location);
		}
		
		virtual bool runOnModule(Module& m) override
		{
			layout = &m.getDataLayout();
			InitializeAliasAnalysis(this, layout);
			
			// HACKHACK: library data
			systemv_abi(m.getFunction("x86_100000f68"), 2); // 2-arg printf
			systemv_abi(m.getFunction("x86_100000f6e"), 3); // strtol
			
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
			
			// Create map entry early. This is important to stop infinite recursion.
			auto& resultMap = registerUse[fn];
			
			Argument* regs = fn->arg_begin();
			// assume x86 regs as first parameter
			assert(cast<PointerType>(regs->getType())->getTypeAtIndex(int(0))->getStructName() == "struct.x86_regs");
			
			// Find all GEPs
			unordered_multimap<const char*, User*> registerUsers;
			for (User* user : regs->users())
			{
				if (const char* registerName = registerNameForPointerOperand(*user))
				{
					registerUsers.insert({registerName, user});
				}
			}
			
			// Find all users of these GEPs
			DominatorsPerRegister gepUsers;
			for (auto iter = registerUsers.begin(); iter != registerUsers.end(); iter++)
			{
				addAllUsers(*iter->second, iter->first, gepUsers);
			}
			
			DominatorTree& preDom = getAnalysis<DominatorTreeWrapperPass>(*fn).getDomTree();
			PostDominatorTree& postDom = getAnalysis<PostDominatorTree>(*fn);
			
			// Add calls
			SmallVector<CallInst*, 8> calls;
			CallGraph& cg = getAnalysis<CallGraphWrapperPass>().getCallGraph();
			CallGraphNode* thisFunc = cg[fn];
			for (const auto& pair : *thisFunc)
			{
				Function* callee = pair.second->getFunction();
				runOnFunction(callee);
				const auto& registerMap = registerUse[callee];
				if (registerMap.size() == 0)
				{
					// recursion
					continue;
				}
				
				// pair.first is a weak value handle and has a cast operator to get the pointee
				CallInst* caller = cast<CallInst>((Value*)pair.first);
				calls.push_back(caller);
				
				for (const auto& useInfo : registerMap)
				{
					gepUsers[useInfo.first].insert(caller);
				}
			}
			
			// Start out resultMap based on call dominance. Weed out calls until dominant call set has been established.
			// This map will be refined by results from mod/ref instruction analysis. The purpose is mainly to define
			// mod/ref behavior for registers that are used in callees of this function, but not in this function
			// directly.
			while (calls.size() > 0)
			{
				unordered_map<const char*, unsigned> callResult;
				auto dominant = findDominantValues(preDom, calls);
				for (CallInst* call : dominant)
				{
					Function* callee = call->getCalledFunction();
					for (const auto& pair : registerUse[callee])
					{
						callResult[pair.first] |= pair.second;
					}
					
					calls.erase(find(calls.begin(), calls.end(), call));
				}
				
				for (const auto& pair : callResult)
				{
					resultMap[pair.first] = static_cast<ModRefResult>(pair.second);
				}
			}
			
			// Find the dominant use(s)
			auto preDominatingUses = gepUsers;
			for (auto& pair : preDominatingUses)
			{
				pair.second = findDominantValues(preDom, pair.second);
			}
			
			// Fill out ModRef use dictionary
			// (Ref info is incomplete)
			for (auto& pair : preDominatingUses)
			{
				ModRefResult& r = resultMap[pair.first];
				r = IncompleteRef;
				for (auto inst : pair.second)
				{
					if (isa<StoreInst>(inst))
					{
						// If we see a dominant store, then the register is modified.
						r = Mod;
						break;
					}
					if (CallInst* call = dyn_cast<CallInst>(inst))
					{
						// If the first user is a call, propagate its ModRef value.
						r = registerUse[call->getCalledFunction()][pair.first];
						break;
					}
				}
			}
			
			// Find post-dominating stores
			auto postDominatingUses = gepUsers;
			for (auto& pair : postDominatingUses)
			{
				const char* key = pair.first;
				auto& set = pair.second;
				// remove non-Mod instructions
				for (auto iter = set.begin(); iter != set.end(); )
				{
					if (isa<StoreInst>(*iter))
					{
						iter++;
						continue;
					}
					else if (CallInst* call = dyn_cast<CallInst>(*iter))
					{
						auto callee = call->getCalledFunction();
						if ((registerUse[callee][key] & Mod) == Mod)
						{
							iter++;
							continue;
						}
					}
					iter = set.erase(iter);
				}
				
				set = findDominantValues(postDom, set);
			}
			
			MemorySSA mssa(*fn);
			mssa.buildMemorySSA(this, &preDom);
			
			// Walk up post-dominating uses until we get to liveOnEntry.
			for (auto& pair : postDominatingUses)
			{
				walkUpPostDominatingUse(mssa, preDominatingUses, postDominatingUses, resultMap, pair.first);
			}
			
			dumpFn(fn);
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
		
		void walkUpPostDominatingUse(MemorySSA& mssa, DominatorsPerRegister& preDominatingUses, DominatorsPerRegister& postDominatingUses, unordered_map<const char*, ModRefResult>& resultMap, const char* regName)
		{
			ModRefResult& queryResult = resultMap[regName];
			if ((queryResult & Incomplete) != Incomplete)
			{
				// Only incomplete results should be considered.
				return;
			}
			
			bool preservesRegister = true;
			for (Instruction* postDominator : postDominatingUses[regName])
			{
				if (StoreInst* store = dyn_cast<StoreInst>(postDominator))
				{
					preservesRegister &= backtrackDefinitionToEntry(mssa, *store);
					if (preservesRegister)
					{
						continue;
					}
				}
				
				// non-store Mod instructions (like calls) automatically kill the definition.
				preservesRegister = false;
				break;
			}
			
			unsigned intQueryResult = queryResult;
			intQueryResult &= ~Incomplete;
			
			if (preservesRegister)
			{
				intQueryResult &= ~Mod;
				
				if (intQueryResult & Ref)
				{
					// Are we reading the value for any other purpose than storing it?
					// If so, there is still a Ref dependency.
					auto& preDom = preDominatingUses[regName];
					assert(preDom.size() > 0);
					if (preDom.size() == 1)
					{
						auto use = *preDom.begin();
						if (auto load = dyn_cast<LoadInst>(use))
						{
							auto range = load->users();
							auto iter = range.begin();
							iter++;
							if (iter == range.end())
							{
								// Single use of load result, register's value is not used.
								intQueryResult &= ~Ref;
							}
						}
					}
				}
			}
			else
			{
				intQueryResult |= Mod;
			}
			
			queryResult = static_cast<ModRefResult>(intQueryResult);
		}
		
		bool backtrackDefinitionToEntry(MemorySSA& mssa, StoreInst& inst)
		{
			ExpressionContext ctx;
			Value* storedValue = inst.getValueOperand();
			if (auto backtracked = backtrackExpressionOfValue(mssa, ctx, storedValue))
			{
				auto simplified = ctx.simplify(backtracked);
				if (auto live = dyn_cast_or_null<LiveOnEntryExpression>(simplified))
				{
					const char* storeAt = registerNameForPointerOperand(*inst.getPointerOperand());
					const char* liveValue = live->getRegisterName();
					return strcmp(storeAt, liveValue) == 0;
				}
			}
			return false;
		}
		
		Expression* backtrackExpressionOfValue(MemorySSA& mssa, ExpressionContext& context, Value* value)
		{
			if (auto constant = dyn_cast<ConstantInt>(value))
			{
				return context.createConstant(constant->getValue());
			}
			
			if (auto load = dyn_cast<LoadInst>(value))
			{
				// For registers, follow memory SSA. For program memory, do a leap of faith and assume ~Mod for every
				// location restored. This is an UNSAFE solution to a largely UNCOMPUTABLE problem.
				auto pointerOperand = load->getPointerOperand();
				if (cast<PointerType>(pointerOperand->getType())->getAddressSpace() == 0)
				{
					MemoryAccess* parent = mssa.getMemoryAccess(load)->getDefiningAccess();
					if (isa<MemoryPhi>(parent))
					{
						// too hard, bail out
						return nullptr;
					}
					
					if (mssa.isLiveOnEntryDef(parent))
					{
						if (const char* reg = registerNameForPointerOperand(*load->getPointerOperand()))
						{
							return context.createLiveOnEntry(reg);
						}
						return nullptr;
					}
					
					// will die on non-trivial expressions
					return backtrackExpressionOfValue(mssa, context, parent->getMemoryInst());
				}
				else
				{
					// Poor man's AA: find other instructions that use the same pointer operand. Expect a single load
					// and a single store for a preserved register.
					LoadInst* load = nullptr;
					StoreInst* store = nullptr;
					for (User* user : pointerOperand->users())
					{
						if (LoadInst* asLoad = dyn_cast<LoadInst>(user))
						{
							if (load == nullptr)
							{
								load = asLoad;
							}
							else
							{
								load = nullptr;
								break;
							}
						}
						else if (StoreInst* asStore = dyn_cast<StoreInst>(user))
						{
							if (store == nullptr)
							{
								store = asStore;
							}
							else
							{
								store = nullptr;
								break;
							}
						}
						else
						{
							load = nullptr;
							store = nullptr;
							break;
						}
					}
					
					if (load != nullptr && store != nullptr)
					{
						return backtrackExpressionOfValue(mssa, context, store->getValueOperand());
					}
					return nullptr;
				}
			}
			
			if (auto store = dyn_cast<StoreInst>(value))
			{
				return backtrackExpressionOfValue(mssa, context, store->getValueOperand());
			}
			
			if (auto binOp = dyn_cast<BinaryOperator>(value))
			{
				auto left = backtrackExpressionOfValue(mssa, context, binOp->getOperand(0));
				auto right = backtrackExpressionOfValue(mssa, context, binOp->getOperand(1));
				if (left != nullptr && right != nullptr)
				{
					switch (binOp->getOpcode())
					{
						case BinaryOperator::Sub:
							right = context.createNegate(right); // fallthrough
						case BinaryOperator::Add:
							return context.createAdd(left, right);
							
						default: break;
					}
				}
				return nullptr;
			}
			
			return nullptr;
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
			// not reading from a register unless the GEP is from the function's first parameter
			const Function* fn = gep.getParent()->getParent();
			if (gep.getOperand(0) != fn->arg_begin())
			{
				return nullptr;
			}
			
			APInt offset(64, 0, false);
			if (gep.accumulateConstantOffset(*layout, offset))
			{
				constexpr size_t size = 8;
				size_t registerOffset = offset.getLimitedValue() & ~(size-1);
				return x86_get_register_name(registerOffset, size);
			}
			else
			{
				return nullptr;
			}
		}
		
		// HACKHACK
		void systemv_abi(Function* fn, size_t argCount)
		{
			static const char* const argumentRegs[] = {
				"rdi", "rsi", "rdx", "rcx", "r8", "r9"
			};
			
			auto& table = registerUse[fn];
			table[x86_unique_register_name("rax")] = Mod;
			table[x86_unique_register_name("r10")] = Mod;
			table[x86_unique_register_name("r11")] = Mod;
			
			table[x86_unique_register_name("rip")] = Ref;
			table[x86_unique_register_name("rbp")] = Ref;
			table[x86_unique_register_name("rsp")] = Ref;
			
			table[x86_unique_register_name("rbx")] = NoModRef;
			table[x86_unique_register_name("r12")] = NoModRef;
			table[x86_unique_register_name("r13")] = NoModRef;
			table[x86_unique_register_name("r14")] = NoModRef;
			table[x86_unique_register_name("r15")] = NoModRef;
			
			for (size_t i = 0; i < countof(argumentRegs); i++)
			{
				const char* uniqued = x86_unique_register_name(argumentRegs[i]);
				table[uniqued] = i < argCount ? ModRef : Mod;
			}
		}
		
		// debug
		void dumpFn(const Function* fn)
		{
			cout << fn->getName().str() << endl;
			auto iter = registerUse.find(fn);
			if (iter != registerUse.end())
			{
				for (auto& pair : iter->second)
				{
					cout << pair.first << ": " << modRefAsString(pair.second) << endl;
				}
			}
			cout << endl;
		}
		
		void dumpDom(const DominatorsPerRegister& doms)
		{
			for (const auto& pair : doms)
			{
				cout << pair.first << ":\n";
				for (const auto* use : pair.second)
				{
					use->dump();
				}
			}
			cout << endl;
		}
	};
	
	char RegisterUse::ID = 0;
}

INITIALIZE_AG_PASS_BEGIN(RegisterUse, AliasAnalysis, "reguse", "ModRef info for registers", true, true, false)
INITIALIZE_PASS_DEPENDENCY(CallGraphWrapperPass)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(MemorySSALazy)
INITIALIZE_PASS_DEPENDENCY(PostDominatorTree)
INITIALIZE_AG_PASS_END(RegisterUse, AliasAnalysis, "reguse", "ModRef info for registers", true, true, false)

ModulePass* createRegisterUsePass()
{
	auto hackhack_dumpFn = &RegisterUse::dumpFn;
	auto hackhack_dumpDom = &RegisterUse::dumpDom;
	return new RegisterUse;
}

