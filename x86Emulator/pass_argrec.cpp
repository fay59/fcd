//
//  pass_argrec.cpp
//  x86Emulator
//
//  Created by Félix on 2015-06-10.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#include "llvm_warnings.h"
#include "passes.h"
#include "x86_register_map.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/CallGraphSCCPass.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <iostream>

using namespace llvm;
using namespace std;

#pragma mark IMPORTANT NOTICE
// This will need to be modified to make sense for indirect calls, since these need to have uniform arguments.

namespace
{
	// HACKHACK: copied over from ArgRec
	// (should be part of some ImmutablePass with global state)
	const char* registerNameForGep(const DataLayout& layout, const GetElementPtrInst& gep)
	{
		// not reading from a register unless the GEP is from the function's first parameter
		const Function* fn = gep.getParent()->getParent();
		if (gep.getOperand(0) != fn->arg_begin())
		{
			return nullptr;
		}
		
		APInt offset(64, 0, false);
		if (gep.accumulateConstantOffset(layout, offset))
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
	
	bool isStructType(Value* val)
	{
		PointerType* regsType = dyn_cast<PointerType>(val->getType());
		if (regsType == nullptr)
		{
			return false;
		}
		StructType* pointeeType = dyn_cast<StructType>(regsType->getTypeAtIndex(int(0)));
		if (pointeeType == nullptr)
		{
			return false;
		}
		
		// HACKHACK: hard-coded register struct type. This should allow other register structs.
		return pointeeType->getStructName() == "struct.x86_regs";
	}
	
	struct ArgumentRecovery : public CallGraphSCCPass
	{
		static char ID;
		const DataLayout* layout;
		unordered_map<const Function*, unordered_multimap<const char*, Value*>> registerAddresses;
		
		ArgumentRecovery() : CallGraphSCCPass(ID)
		{
		}
		
		virtual void getAnalysisUsage(AnalysisUsage& au) const override
		{
			au.addRequired<AliasAnalysis>();
			au.addRequired<RegisterUse>();
			au.addRequired<CallGraphWrapperPass>();
			CallGraphSCCPass::getAnalysisUsage(au);
		}
		
		virtual bool doInitialization(CallGraph& cg) override
		{
			layout = &cg.getModule().getDataLayout();
			return CallGraphSCCPass::doInitialization(cg);
		}
		
		virtual bool doFinalization(CallGraph& cg) override
		{
			registerAddresses.clear();
			return CallGraphSCCPass::doFinalization(cg);
		}
		
		virtual bool runOnSCC(CallGraphSCC& scc) override
		{
			bool changed = false;
			for (auto iter = scc.begin(); iter != scc.end(); ++iter)
			{
				if (auto newNode = recoverArguments(*iter))
				{
					changed = true;
					scc.ReplaceNode(*iter, newNode);
				}
			}
			return changed;
		}
		
		CallGraphNode* recoverArguments(CallGraphNode* node);
		unordered_multimap<const char*, Value*>& exposeAllRegisters(Function* fn);
	};
	
	char ArgumentRecovery::ID = 0;
	RegisterPass<ArgumentRecovery> argrec("argrec", "Change functions to accept arguments instead of register struct", false, false);
}

CallGraphNode* ArgumentRecovery::recoverArguments(llvm::CallGraphNode *node)
{
	Function* fn = node->getFunction();
	if (fn == nullptr)
	{
		// "theoretical nodes", whatever that is
		return nullptr;
	}
	
	if (fn->arg_size() != 1)
	{
		// quick exit if there isn't exactly one argument
		return nullptr;
	}
	
	Argument* fnArg = fn->arg_begin();
	if (!isStructType(fnArg))
	{
		return nullptr;
	}
	
	// This is a nasty NASTY hack that relies on the AA pass being RegisterUse.
	// The data should be moved to a separate helper pass that can be queried from both the AA pass and this one.
	RegisterUse& regUse = getAnalysis<RegisterUse>();
	CallGraph& cg = getAnalysis<CallGraphWrapperPass>().getCallGraph();
	
	const auto* modRefInfo = regUse.getModRefInfo(fn);
	assert(modRefInfo != nullptr);
	
	// At this point we pretty much know that we're going to modify the function, so start doing that.
	// Create a new function prototype, asking RegisterUse for which registers should be passed in, and how.
	
	LLVMContext& ctx = fn->getContext();
	SmallVector<pair<const char*, Type*>, 16> parameters;
	Type* int64 = Type::getInt64Ty(ctx);
	Type* int64ptr = Type::getInt64PtrTy(ctx);
	for (const auto& pair : *modRefInfo)
	{
		if (pair.second != RegisterUse::NoModRef)
		{
			Type* paramType = (pair.second & RegisterUse::Mod) == RegisterUse::Mod ? int64ptr : int64;
			parameters.push_back({pair.first, paramType});
		}
	}
	
	// Order parameters. This could use an ABI-specific sort routine. For now, use a lexicographical sort.
	sort(parameters.begin(), parameters.end(), [](const pair<const char*, Type*>& a, const pair<const char*, Type*>& b) {
		return strcmp(a.first, b.first) < 0;
	});
	
	// Extract parameter types.
	SmallVector<Type*, 16> parameterTypes;
	for (const auto& pair : parameters)
	{
		parameterTypes.push_back(pair.second);
	}
	
	// Ideally, we would also do caller analysis here to figure out which output registers are never read, such that
	// we can either eliminate them from the parameter list or pass them by value instead of by address.
	// We would also pick a return value.
	FunctionType* newFunctionType = FunctionType::get(Type::getVoidTy(ctx), parameterTypes, false);

	Function* newFunc = Function::Create(newFunctionType, fn->getLinkage());
	newFunc->copyAttributesFrom(fn);
	fn->getParent()->getFunctionList().insert(fn, newFunc);
	newFunc->takeName(fn);
	
	// Set argument names to help with debugging
	size_t i = 0;
	for (Argument& arg : newFunc->args())
	{
		arg.setName(parameters[i].first);
		i++;
	}
	
	// update call graph
	CallGraphNode* newFuncNode = cg.getOrInsertFunction(newFunc);
	
	// loop over callers and transform call sites.
	while (!fn->use_empty())
	{
		CallSite cs(fn->user_back());
		Instruction* call = cast<CallInst>(cs.getInstruction());
		Function* caller = call->getParent()->getParent();
		
		auto& registerPositions = exposeAllRegisters(caller);
		SmallVector<Value*, 16> callParameters;
		for (const auto& pair : parameters)
		{
			// HACKHACK: find a pointer to a 64-bit int in the set.
			Value* registerPointer = nullptr;
			auto range = registerPositions.equal_range(pair.first);
			for (auto iter = range.first; iter != range.second; iter++)
			{
				if (auto gep = dyn_cast<GetElementPtrInst>(iter->second))
				{
					if (gep->getResultElementType() == int64ptr)
					{
						registerPointer = gep;
						break;
					}
				}
			}
			
			assert(registerPointer != nullptr);
			
			if (isa<PointerType>(pair.second))
			{
				callParameters.push_back(registerPointer);
			}
			else
			{
				// Find a load.
				// This could be a little naive as it sits on the assumption that everything is either an int64 or
				// an int64*.
				LoadInst* load = nullptr;
				for (User* user : registerPointer->users())
				{
					if (auto userAsLoad = dyn_cast<LoadInst>(user))
					{
						load = userAsLoad;
						break;
					}
				}
				if (load == nullptr)
				{
					// No load found? Make one!
					load = new LoadInst(registerPointer, pair.first, call);
				}
				callParameters.push_back(load);
			}
		}
		CallInst* newCall = CallInst::Create(newFunc, callParameters);
		call->replaceAllUsesWith(newCall);
		
		// Update call graph
		CallGraphNode* calleeNode = cg[caller];
		calleeNode->replaceCallEdge(cs, CallSite(newCall), newFuncNode);
		
		// Update AA
		regUse.replaceWithNewValue(call, newCall);
		newCall->takeName(call);
		call->eraseFromParent();
	}
	
	// Get register offsets from the old function before we start mutilating it.
	auto& registerMap = exposeAllRegisters(fn);
	
	// Fix up function code. Start by moving everything into the new function.
	newFunc->getBasicBlockList().splice(newFunc->begin(), fn->getBasicBlockList());
	
	// Change register uses
	size_t argIndex = 0;
	auto& argList = newFunc->getArgumentList();
	Instruction* allocaInsertionPoint = newFunc->begin()->begin();
	for (auto iter = argList.begin(); iter != argList.end(); iter++)
	{
		Value* replaceWith = iter;
		const auto& paramTuple = parameters[argIndex];
		if (!isa<PointerType>(paramTuple.second))
		{
			// Create an alloca, copy value from parameter, replace GEP with alloca.
			// This is ugly code gen, but it will optimize easily, and still work if
			// we need a pointer reference to the register.
			auto alloca = new AllocaInst(paramTuple.second, paramTuple.first, allocaInsertionPoint);
			new StoreInst(iter, alloca, allocaInsertionPoint);
			replaceWith = alloca;
		}
		
		// Replace all uses with new instance.
		auto iterPair = registerMap.equal_range(paramTuple.first);
		for (auto iter = iterPair.first; iter != iterPair.second; iter++)
		{
			auto& registerValue = iter->second;
			registerValue->replaceAllUsesWith(replaceWith);
			cast<Instruction>(registerValue)->eraseFromParent();
			registerValue = replaceWith;
		}
	}
	
	// At this point, the uses of the argument struct left should be registers that are preserved.
	// Promote these to allocas. Their undefined uses will be optimized away.
	while (!fnArg->use_empty())
	{
		auto user = cast<GetElementPtrInst>(fnArg->user_back());
		const char* regName = registerNameForGep(*layout, *user);
		auto alloca = new AllocaInst(user->getResultElementType()->getPointerElementType(), regName, allocaInsertionPoint);
		user->replaceAllUsesWith(alloca);
		user->eraseFromParent();
	}
	
	// At this point nothing should be using the old register argument anymore. (Pray!)
	// Leave the hollow husk of the old function in place to be erased by global DCE.
	registerAddresses[newFunc] = move(registerMap);
	registerAddresses.erase(fn);
	
	// Should be all.
	return newFuncNode;
}

unordered_multimap<const char*, Value*>& ArgumentRecovery::exposeAllRegisters(llvm::Function* fn)
{
	auto iter = registerAddresses.find(fn);
	if (iter != registerAddresses.end())
	{
		return iter->second;
	}
	
	auto& addresses = registerAddresses[fn];
	Argument* firstArg = fn->arg_begin();
	assert(isStructType(firstArg));
	
	// Get explicitly-used GEPs
	for (User* user : firstArg->users())
	{
		if (auto gep = dyn_cast<GetElementPtrInst>(user))
		{
			const char* name = registerNameForGep(*layout, *gep);
			
			cerr << name << ": ";
			gep->dump();
			
			addresses.insert({name, gep});
		}
	}
	
	// Synthesize GEPs for implicitly-used registers.
	// Implicit uses are when a function callee uses a register without there being a reference in the caller.
	// This happens either because the parameter is passed through, or because the register is a scratch register that
	// the caller doesn't use itself.
	assert(!"Implement me");
	cerr << endl;
	
	return addresses;
}

CallGraphSCCPass* createArgumentRecoveryPass()
{
	return new ArgumentRecovery;
}
