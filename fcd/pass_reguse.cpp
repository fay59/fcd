//
// pass_reguse.cpp
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

#include "llvm_warnings.h"

#include <iostream>

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/SCCIterator.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/MemoryDependenceAnalysis.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/Analysis/RegionPass.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_os_ostream.h>
#include "MemorySSA.h"
SILENCE_LLVM_WARNINGS_END()

#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "pass_reguse.h"
#include "symbolic_expr.h"
#include "x86_register_map.h"

using namespace llvm;
using namespace std;
using namespace symbolic;

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
	TCollection findDominantValues(TDomTree& dom, const TCollection& set)
	{
		TCollection result;
		for (const auto& item : set)
		{
			bool dominated = any_of(set.begin(), set.end(), [&](const typename TCollection::value_type& otherItem)
			{
				return item != otherItem && dominates(dom, otherItem, item);
			});
			
			if (!dominated)
			{
				result.insert(result.end(), item);
			}
		}
		return result;
	}
	
	void addAllUsers(User& i, const char* reg, unordered_map<const char*, unordered_set<Instruction*>>& allUsers)
	{
		assert(reg != nullptr);
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
	
	Expression* backtrackExpressionOfValue(const TargetInfo& target, MemorySSA& mssa, ExpressionContext& context, Value* value)
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
					const char* regMaybe = target.registerName(*load->getPointerOperand());
					if (const char* reg = target.largestOverlappingRegister(regMaybe))
					{
						return context.createLiveOnEntry(reg);
					}
					return nullptr;
				}
				
				// will die on non-trivial expressions
				return backtrackExpressionOfValue(target, mssa, context, parent->getMemoryInst());
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
					return backtrackExpressionOfValue(target, mssa, context, store->getValueOperand());
				}
				return nullptr;
			}
		}
		
		if (auto store = dyn_cast<StoreInst>(value))
		{
			return backtrackExpressionOfValue(target, mssa, context, store->getValueOperand());
		}
		
		if (auto binOp = dyn_cast<BinaryOperator>(value))
		{
			auto left = backtrackExpressionOfValue(target, mssa, context, binOp->getOperand(0));
			auto right = backtrackExpressionOfValue(target, mssa, context, binOp->getOperand(1));
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
	
	bool backtrackDefinitionToEntry(const TargetInfo& target, MemorySSA& mssa, StoreInst& inst)
	{
		ExpressionContext ctx;
		Value* storedValue = inst.getValueOperand();
		if (auto backtracked = backtrackExpressionOfValue(target, mssa, ctx, storedValue))
		{
			auto simplified = ctx.simplify(backtracked);
			if (auto live = dyn_cast_or_null<LiveOnEntryExpression>(simplified))
			{
				const char* maybeStoreAt = target.registerName(*inst.getPointerOperand());
				if (const char* storeAt = target.largestOverlappingRegister(maybeStoreAt))
				{
					const char* liveValue = live->getRegisterName();
					return strcmp(storeAt, liveValue) == 0;
				}
			}
		}
		return false;
	}
	
	void walkUpPostDominatingUse(const TargetInfo& target, MemorySSA& mssa, RegisterUse::DominatorsPerRegister& preDominatingUses, RegisterUse::DominatorsPerRegister& postDominatingUses, unordered_map<const char*, RegisterUse::ModRefResult>& resultMap, const char* regName)
	{
		assert(regName != nullptr);
		RegisterUse::ModRefResult& queryResult = resultMap[regName];
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
				preservesRegister &= backtrackDefinitionToEntry(target, mssa, *store);
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
			intQueryResult &= ~RegisterUse::Mod;
			
			if (intQueryResult & RegisterUse::Ref)
			{
				// Are we reading the value for any other purpose than storing it?
				// If so, there is still a Ref dependency.
				auto& preDom = preDominatingUses[regName];
				assert(preDom.size() > 0);
				if (preDom.size() == 1)
				{
					auto use = *preDom.begin();
					if (auto load = dyn_cast<LoadInst>(use))
					if (load->hasOneUse())
					{
						// Single use of load result. If it's just stored, remove Ref dependency.
						auto user = *load->user_begin();
						if (isa<StoreInst>(user))
						{
							// XXX: if you have issues with Undef values popping up, check this one out. The heuristic
							// will probably need to be extended to verify that the stored value is loaded back
							// unaltered.
							intQueryResult &= ~RegisterUse::Ref;
						}
					}
				}
			}
		}
		else
		{
			intQueryResult |= RegisterUse::Mod;
		}
		
		queryResult = static_cast<RegisterUse::ModRefResult>(intQueryResult);
	}
}

RegisterUse::RegisterUse()
: ModulePass(ID)
{
}

RegisterUse::RegisterUse(const RegisterUse& that)
: ModulePass(ID), registerUse(that.registerUse)
{
}

const char* RegisterUse::getPassName() const
{
	return "Argument Recovery";
}

void RegisterUse::getAnalysisUsage(llvm::AnalysisUsage& au) const
{
	AliasAnalysis::getAnalysisUsage(au);
	au.addRequired<CallGraphWrapperPass>();
	au.addRequired<DominatorTreeWrapperPass>();
	au.addRequired<PostDominatorTree>();
	au.addRequired<TargetInfo>();
	au.setPreservesAll();
}

void* RegisterUse::getAdjustedAnalysisPointer(llvm::AnalysisID PI)
{
	if (PI == &AliasAnalysis::ID)
		return (AliasAnalysis*)this;
	return this;
}

unordered_map<const char*, RegisterUse::ModRefResult>& RegisterUse::getOrCreateModRefInfo(llvm::Function *fn)
{
	return registerUse[fn];
}

const unordered_map<const char*, RegisterUse::ModRefResult>* RegisterUse::getModRefInfo(llvm::Function *fn) const
{
	auto iter = registerUse.find(fn);
	return iter == registerUse.end() ? nullptr : &iter->second;
}

RegisterUse::ModRefResult RegisterUse::getModRefInfo(llvm::Function *fn, const char *registerName) const
{
	auto iter = registerUse.find(fn);
	if (iter != registerUse.end())
	{
		const char* canon = getAnalysis<TargetInfo>().keyName(registerName);
		auto regIter = iter->second.find(canon);
		if (regIter != iter->second.end())
		{
			return regIter->second;
		}
	}
	return NoModRef;
}

RegisterUse::ModRefResult RegisterUse::getModRefInfo(ImmutableCallSite cs, const MemoryLocation& location)
{
	if (auto inst = dyn_cast<CallInst>(cs.getInstruction()))
	{
		auto iter = registerUse.find(inst->getCalledFunction());
		// The data here is incomplete when used for recursive calls. Any register that isn't trivially declared
		// Mod is declared Ref only. This is on purpose, as it allows us to bypass recursive calls to determine
		// if, notwithstanding the call itself, the function can modify the queried register.
		if (iter != registerUse.end())
		{
			const auto& target = getAnalysis<TargetInfo>();
			const char* maybeName = target.registerName(*location.Ptr);
			const char* registerName = target.largestOverlappingRegister(maybeName);
			auto regIter = iter->second.find(registerName);
			return regIter == iter->second.end() ? NoModRef : regIter->second;
		}
	}
	
	// no idea
	return AliasAnalysis::getModRefInfo(cs, location);
}

bool RegisterUse::runOnModule(llvm::Module &m)
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

void RegisterUse::runOnSCC(CallGraphSCC& scc)
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
}

void RegisterUse::runOnFunction(Function* fn)
{
	// Recursive calls to this function are likely for non-singular SSCs.
	if (registerUse.find(fn) != registerUse.end())
	{
		return;
	}
	
	// Create map entry early. This is important to stop infinite recursion.
	auto& resultMap = registerUse[fn];
	
	Argument* regs = fn->arg_begin();
	
	// HACKHACK: assume x86 regs as first parameter.
	auto pointerType = dyn_cast<PointerType>(regs->getType());
	if (pointerType == nullptr || pointerType->getTypeAtIndex(int(0))->getStructName() != "struct.x86_regs")
	{
		return;
	}
	
	// Find all GEPs
	const auto& target = getAnalysis<TargetInfo>();
	unordered_multimap<const char*, User*> registerUsers;
	for (User* user : regs->users())
	{
		if (const char* maybeRegister = target.registerName(*user))
		{
			const char* registerName = target.largestOverlappingRegister(maybeRegister);
			assert(registerName != nullptr);
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
		walkUpPostDominatingUse(target, mssa, preDominatingUses, postDominatingUses, resultMap, pair.first);
	}
}

#pragma mark DEBUG
void RegisterUse::dumpFn(const Function* fn) const
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

void RegisterUse::dumpDom(const DominatorsPerRegister& doms) const
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

char RegisterUse::ID = 0;

INITIALIZE_AG_PASS_BEGIN(RegisterUse, AliasAnalysis, "reguse", "ModRef info for registers", true, true, false)
INITIALIZE_PASS_DEPENDENCY(TargetInfo)
INITIALIZE_PASS_DEPENDENCY(CallGraphWrapperPass)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(MemorySSALazy)
INITIALIZE_PASS_DEPENDENCY(PostDominatorTree)
INITIALIZE_AG_PASS_END(RegisterUse, AliasAnalysis, "reguse", "ModRef info for registers", true, true, false)

RegisterUse* createRegisterUsePass()
{
	return new RegisterUse;
}

