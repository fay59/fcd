//
// anyarch_anycc.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "anyarch_anycc.h"
#include "cc_common.h"
#include "main.h"
#include "metadata.h"
#include "symbolic_expr.h"

#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/Constants.h>

#include <unordered_map>
#include <unordered_set>

using namespace llvm;
using namespace std;
using namespace symbolic;
using SExpression = symbolic::Expression;

namespace
{
	RegisterCallingConvention<CallingConvention_AnyArch_AnyCC> registerAnyAny;
	
	typedef unordered_map<const TargetRegisterInfo*, unordered_set<Instruction*>> DominatorsPerRegister;
	typedef std::unordered_map<const TargetRegisterInfo*, llvm::ModRefInfo> ModRefMap;

	constexpr auto Incomplete = static_cast<ModRefInfo>(4);
	constexpr auto IncompleteRef = static_cast<ModRefInfo>(Incomplete | MRI_Ref);
	
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
	
	ModRefInfo& operator|=(ModRefInfo& a, ModRefInfo b)
	{
		a = static_cast<ModRefInfo>(a | b);
		return a;
	}
	
	void addAllUsers(User& i, const TargetRegisterInfo* reg, unordered_map<const TargetRegisterInfo*, unordered_set<Instruction*>>& allUsers)
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
	
	unordered_map<const TargetRegisterInfo*, ModRefInfo> translateToModRef(const CallInformation& callInfo)
	{
		unordered_map<const TargetRegisterInfo*, ModRefInfo> result;
		auto returnCutoff = callInfo.return_begin();
		for (auto iter = callInfo.begin(); iter != callInfo.end(); ++iter)
		{
			if (iter->type == ValueInformation::IntegerRegister)
			{
				result[iter->registerInfo] |= iter < returnCutoff ? MRI_Ref : MRI_Mod;
			}
		}
		return result;
	}
	
	SExpression* backtrackSExpressionOfValue(const TargetInfo& target, MemorySSA& mssa, ExpressionContext& context, Value* value)
	{
		if (auto constant = dyn_cast<ConstantInt>(value))
		{
			return context.createConstant(constant->getValue());
		}
		
		if (auto load = dyn_cast<LoadInst>(value))
		{
			// For registers, follow memory SSA. For program memory, do a leap of faith and assume ~Mod for every
			// location restored. This is an UNSAFE solution to a largely UNCOMPUTABLE problem.
			if (!md::isProgramMemory(*load))
			{
				MemoryAccess* parent = cast<MemoryUse>(mssa.getMemoryAccess(load))->getDefiningAccess();
				if (auto useOrDef = cast<MemoryUseOrDef>(parent))
				{
					if (mssa.isLiveOnEntryDef(parent))
					{
						if (const TargetRegisterInfo* regMaybe = target.registerInfo(*load->getPointerOperand()))
						{
							const TargetRegisterInfo& reg = target.largestOverlappingRegister(*regMaybe);
							return context.createLiveOnEntry(&reg);
						}
						return nullptr;
					}
					
					// will die on non-trivial SExpressions
					return backtrackSExpressionOfValue(target, mssa, context, useOrDef->getMemoryInst());
				}
				else
				{
					// implies isa<MemoryPhi>(parent)
					// too hard, bail out
					return nullptr;
				}
			}
			else
			{
				// Poor man's AA: find other instructions that use the same pointer operand. Expect a single load
				// and a single store for a preserved register.
				LoadInst* preservingLoad = nullptr;
				StoreInst* preservingStore = nullptr;
				for (User* user : load->getPointerOperand()->users())
				{
					if (LoadInst* asLoad = dyn_cast<LoadInst>(user))
					{
						if (preservingLoad == nullptr)
						{
							preservingLoad = asLoad;
						}
						else
						{
							preservingLoad = nullptr;
							break;
						}
					}
					else if (StoreInst* asStore = dyn_cast<StoreInst>(user))
					{
						if (preservingStore == nullptr)
						{
							preservingStore = asStore;
						}
						else
						{
							preservingStore = nullptr;
							break;
						}
					}
					else
					{
						preservingLoad = nullptr;
						preservingStore = nullptr;
						break;
					}
				}
				
				if (preservingLoad != nullptr && preservingStore != nullptr)
				{
					return backtrackSExpressionOfValue(target, mssa, context, preservingStore->getValueOperand());
				}
				return nullptr;
			}
		}
		
		if (auto store = dyn_cast<StoreInst>(value))
		{
			return backtrackSExpressionOfValue(target, mssa, context, store->getValueOperand());
		}
		
		if (auto binOp = dyn_cast<BinaryOperator>(value))
		{
			auto left = backtrackSExpressionOfValue(target, mssa, context, binOp->getOperand(0));
			auto right = backtrackSExpressionOfValue(target, mssa, context, binOp->getOperand(1));
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
		if (auto backtracked = backtrackSExpressionOfValue(target, mssa, ctx, storedValue))
		{
			auto simplified = ctx.simplify(backtracked);
			if (auto live = dyn_cast_or_null<LiveOnEntryExpression>(simplified))
			if (const TargetRegisterInfo* maybeStoreAt = target.registerInfo(*inst.getPointerOperand()))
			{
				const TargetRegisterInfo& storeAt = target.largestOverlappingRegister(*maybeStoreAt);
				return live->getRegisterInfo() == &storeAt;
			}
		}
		return false;
	}
	
	void walkUpPostDominatingUse(const TargetInfo& target, MemorySSA& mssa, DominatorsPerRegister& preDominatingUses, DominatorsPerRegister& postDominatingUses, ModRefMap& resultMap, const TargetRegisterInfo* regKey)
	{
		assert(regKey != nullptr);
		ModRefInfo& queryResult = resultMap[regKey];
		if ((queryResult & Incomplete) != Incomplete)
		{
			// Only incomplete results should be considered.
			return;
		}
		
		bool preservesRegister = true;
		for (Instruction* postDominator : postDominatingUses[regKey])
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
		
		int intQueryResult = queryResult;
		intQueryResult &= ~Incomplete;
		
		if (preservesRegister)
		{
			intQueryResult &= ~MRI_Mod;
			
			if (intQueryResult & MRI_Ref)
			{
				// Are we reading the value for any other purpose than storing it?
				// If so, there is still a Ref dependency.
				auto& preDom = preDominatingUses[regKey];
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
							intQueryResult &= ~MRI_Ref;
						}
					}
				}
			}
		}
		else
		{
			intQueryResult |= MRI_Mod;
		}
		
		queryResult = static_cast<ModRefInfo>(intQueryResult);
	}
}

const char* CallingConvention_AnyArch_AnyCC::name = "any/any";

const char* CallingConvention_AnyArch_AnyCC::getName() const
{
	return name;
}

const char* CallingConvention_AnyArch_AnyCC::getHelp() const
{
	return "guess register parameters; needs full disassembly";
}

bool CallingConvention_AnyArch_AnyCC::matches(TargetInfo &target, Executable &executable) const
{
	// Match nothing.
	return false;
}

void CallingConvention_AnyArch_AnyCC::getAnalysisUsage(llvm::AnalysisUsage &au) const
{
	au.addRequired<CallGraphWrapperPass>();
	au.addPreserved<CallGraphWrapperPass>();
	
	au.addRequired<DominatorTreeWrapperPass>();
	au.addPreserved<DominatorTreeWrapperPass>();
	
	au.addRequired<PostDominatorTreeWrapperPass>();
	au.addPreserved<PostDominatorTreeWrapperPass>();
}

bool CallingConvention_AnyArch_AnyCC::analyzeFunction(ParameterRegistry &registry, CallInformation &fillOut, llvm::Function &func)
{
	if (!isFullDisassembly() || md::isPrototype(func))
	{
		return false;
	}
	
	auto regs = &*func.arg_begin();
	unordered_map<const TargetRegisterInfo*, ModRefInfo> resultMap;
	
	// Find all GEPs
	const auto& target = registry.getTargetInfo();
	unordered_multimap<const TargetRegisterInfo*, User*> registerUsers;
	for (User* user : regs->users())
	{
		if (const TargetRegisterInfo* maybeRegister = target.registerInfo(*user))
		{
			const TargetRegisterInfo& registerInfo = target.largestOverlappingRegister(*maybeRegister);
			registerUsers.insert({&registerInfo, user});
		}
	}
	
	// Find all users of these GEPs
	DominatorsPerRegister gepUsers;
	for (auto iter = registerUsers.begin(); iter != registerUsers.end(); iter++)
	{
		addAllUsers(*iter->second, iter->first, gepUsers);
	}
	
	DominatorTree& preDom = registry.getAnalysis<DominatorTreeWrapperPass>(func).getDomTree();
	PostDominatorTree& postDom = registry.getAnalysis<PostDominatorTreeWrapperPass>(func).getPostDomTree();
	
	// Add calls
	SmallVector<CallInst*, 8> calls;
	CallGraph& cg = registry.getAnalysis<CallGraphWrapperPass>().getCallGraph();
	CallGraphNode* thisFunc = cg[&func];
	for (const auto& pair : *thisFunc)
	{
		Function* callee = pair.second->getFunction();
		if (const CallInformation* callInfo = registry.getCallInfo(*callee))
		if (callInfo->getStage() == CallInformation::Completed)
		{
			// pair.first is a weak value handle and has a cast operator to get the pointee
			CallInst* caller = cast<CallInst>((Value*)pair.first);
			calls.push_back(caller);
			
			for (const auto& vi : *callInfo)
			{
				if (vi.type == ValueInformation::IntegerRegister)
				{
					gepUsers[vi.registerInfo].insert(caller);
				}
			}
		}
	}
	
	// Start out resultMap based on call dominance. Weed out calls until dominant call set has been established.
	// This map will be refined by results from mod/ref instruction analysis. The purpose is mainly to define
	// mod/ref behavior for registers that are used in callees of this function, but not in this function
	// directly.
	while (calls.size() > 0)
	{
		unordered_map<const TargetRegisterInfo*, unsigned> callResult;
		auto dominant = findDominantValues(preDom, calls);
		for (CallInst* call : dominant)
		{
			Function* callee = call->getCalledFunction();
			for (const auto& pair : translateToModRef(*registry.getCallInfo(*callee)))
			{
				callResult[pair.first] |= pair.second;
			}
			
			calls.erase(find(calls.begin(), calls.end(), call));
		}
		
		for (const auto& pair : callResult)
		{
			resultMap[pair.first] = static_cast<ModRefInfo>(pair.second);
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
		ModRefInfo& r = resultMap[pair.first];
		r = IncompleteRef;
		for (auto inst : pair.second)
		{
			if (isa<StoreInst>(inst))
			{
				// If we see a dominant store, then the register is modified.
				r = MRI_Mod;
				break;
			}
			if (CallInst* call = dyn_cast<CallInst>(inst))
			{
				// If the first user is a call, propagate its ModRef value.
				r = registry.getCallInfo(*call->getCalledFunction())->getRegisterModRef(*pair.first);
				break;
			}
		}
	}
	
	// Find post-dominating stores
	auto postDominatingUses = gepUsers;
	for (auto& pair : postDominatingUses)
	{
		const TargetRegisterInfo* key = pair.first;
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
				const auto& info = *registry.getCallInfo(*callee);
				if ((info.getRegisterModRef(*key) & MRI_Mod) == MRI_Mod)
				{
					iter++;
					continue;
				}
			}
			iter = set.erase(iter);
		}
		
		set = findDominantValues(postDom, set);
	}
	
	MemorySSA& mssa = *registry.getMemorySSA(func);
	
	// Walk up post-dominating uses until we get to liveOnEntry.
	for (auto& pair : postDominatingUses)
	{
		walkUpPostDominatingUse(target, mssa, preDominatingUses, postDominatingUses, resultMap, pair.first);
	}
	
	// Use resultMap to build call information. First, sort registers by their pointer order; this ensures stable
	// parameter order.
	
	// We have authoritative information on used parameters, but not on return values. Only register parameters in this
	// step.
	SmallVector<pair<const TargetRegisterInfo*, ModRefInfo>, 16> registers;
	copy(resultMap.begin(), resultMap.end(), registers.begin());
	sort(registers.begin(), registers.end());
	
	vector<const TargetRegisterInfo*> returns;
	for (const auto& pair : resultMap)
	{
		if (pair.second & MRI_Ref)
		{
			fillOut.addParameter(ValueInformation::IntegerRegister, pair.first);
		}
		if (pair.second & MRI_Mod)
		{
			returns.push_back(pair.first);
		}
	}
	
	// Check for used returns.
	for (const TargetRegisterInfo* reg : ipaFindUsedReturns(registry, func, returns))
	{
		fillOut.addReturn(ValueInformation::IntegerRegister, reg);
	}
	return true;
}
