//
// pass_argrec.cpp
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

#include <stdio.h>

#include "llvm_warnings.h"
#include "metadata.h"
#include "passes.h"
#include "params_registry.h"

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

using namespace llvm;
using namespace std;

namespace
{
	struct ArgumentRecovery : public CallGraphSCCPass
	{
		static char ID;
		Function* indirectJump;
		Function* indirectCall;
		unordered_map<const Function*, Value*> registerPtr;
		
		ArgumentRecovery() : CallGraphSCCPass(ID)
		{
		}
		
		virtual void getAnalysisUsage(AnalysisUsage& au) const override
		{
			au.addRequired<AliasAnalysis>();
			au.addRequired<CallGraphWrapperPass>();
			au.addRequired<ParameterRegistry>();
			au.addRequired<TargetInfo>();
			CallGraphSCCPass::getAnalysisUsage(au);
		}
		
		virtual bool doInitialization(CallGraph& cg) override
		{
			auto& module = cg.getModule();
			auto& ctx = module.getContext();
			IntegerType* int64 = Type::getInt64Ty(ctx);
			FunctionType* newFunctionType = FunctionType::get(Type::getVoidTy(ctx), {int64}, true);
			indirectJump = Function::Create(newFunctionType, Function::ExternalLinkage, ".indirect_jump_vararg", &module);
			indirectCall = Function::Create(newFunctionType, Function::ExternalLinkage, ".indirect_call_vararg", &module);
			cg.getOrInsertFunction(indirectJump);
			cg.getOrInsertFunction(indirectCall);
			
			return CallGraphSCCPass::doInitialization(cg);
		}
		
		virtual bool runOnSCC(CallGraphSCC& scc) override
		{
			for (auto iter = scc.begin(); iter != scc.end(); ++iter)
			{
				if (Function* fn = (*iter)->getFunction())
				{
					// pre-populate table
					getRegisterPtr(*fn);
				}
			}
			
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
		
		bool isRecoverable(Function& fn)
		{
			return md::getVirtualAddress(fn) != nullptr && !md::hasRecoveredArguments(fn);
		}
		
		Value* getRegisterPtr(Function& fn)
		{
			auto iter = registerPtr.find(&fn);
			if (iter != registerPtr.end())
			{
				return iter->second;
			}
			
			if (!isRecoverable(fn))
			{
				return nullptr;
			}
			
			auto arg = fn.arg_begin();
			registerPtr[&fn] = arg;
			return arg;
		}
		
		Function& createParameterizedFunction(Function& base, const CallInformation& ci);
		void fixCallSites(Function& base, Function& newTarget, const CallInformation& ci);
		Value* createReturnValue(Function& function, const CallInformation& ci, Instruction* insertionPoint);
		void updateFunctionBody(Function& oldFunction, Function& newTarget, const CallInformation& ci);
		CallGraphNode* recoverArguments(CallGraphNode* node);
	};
	
	Function& ArgumentRecovery::createParameterizedFunction(Function& base, const CallInformation& callInfo)
	{
		TargetInfo& info = getAnalysis<TargetInfo>();
		LLVMContext& ctx = base.getContext();
		Type* integer = Type::getIntNTy(ctx, info.getPointerSize() * CHAR_BIT);
		
		SmallVector<Type*, 8> parameterTypes;
		SmallVector<string, 8> parameterNames;
		for (const auto& param : callInfo.parameters())
		{
			if (param.type == ValueInformation::IntegerRegister)
			{
				parameterTypes.push_back(integer);
				parameterNames.push_back(param.registerInfo->name);
			}
			else if (param.type == ValueInformation::Stack)
			{
				parameterTypes.push_back(integer);
				parameterNames.emplace_back();
				raw_string_ostream(parameterNames.back()) << "sp" << param.frameBaseOffset;
			}
			else
			{
				llvm_unreachable("not implemented");
			}
		}
		
		Type* returnType;
		size_t count = callInfo.returns_size();
		if (count == 0)
		{
			returnType = Type::getVoidTy(ctx);
		}
		else if (count == 1)
		{
			const auto& ret = *callInfo.return_begin();
			if (ret.type == ValueInformation::IntegerRegister)
			{
				returnType = integer;
			}
			else
			{
				llvm_unreachable("not implemented");
			}
		}
		else
		{
			SmallVector<Type*, 2> returnTypes;
			for (const auto& ret : callInfo.returns())
			{
				if (ret.type == ValueInformation::IntegerRegister)
				{
					returnTypes.push_back(integer);
				}
				else
				{
					llvm_unreachable("not implemented");
				}
			}
			
			string returnTypeName = (base.getName() + ".return").str();
			returnType = StructType::create(returnTypes, returnTypeName);
		}
		
		assert(!callInfo.isVararg() && "not implemented");
		FunctionType* ft = FunctionType::get(returnType, parameterTypes, false);
		
		Function* newFunc = Function::Create(ft, base.getLinkage());
		newFunc->copyAttributesFrom(&base);
		md::copy(base, *newFunc);
		base.getParent()->getFunctionList().insert(&base, newFunc);
		newFunc->takeName(&base);
		base.setName("__hollow_husk__." + newFunc->getName());
		
		// set parameter names
		size_t i = 0;
		for (Argument& arg : newFunc->args())
		{
			arg.setName(parameterNames[i]);
			i++;
		}
		
		return *newFunc;
	}
	
	void ArgumentRecovery::fixCallSites(Function& base, Function& newTarget, const CallInformation& ci)
	{
		LLVMContext& ctx = base.getContext();
		TargetInfo& targetInfo = getAnalysis<TargetInfo>();
		AliasAnalysis& aa = getAnalysis<AliasAnalysis>();
		CallGraph& cg = getAnalysis<CallGraphWrapperPass>().getCallGraph();
		
		unsigned pointerSize = targetInfo.getPointerSize() * CHAR_BIT;
		Type* integer = Type::getIntNTy(ctx, pointerSize);
		Type* integerPtr = Type::getIntNPtrTy(ctx, pointerSize, 1);
		CallGraphNode* newFuncNode = cg.getOrInsertFunction(&newTarget);
		
		// loop over callers and transform call sites.
		while (!base.use_empty())
		{
			CallSite cs(base.user_back());
			CallInst* call = cast<CallInst>(cs.getInstruction());
			Function* caller = call->getParent()->getParent();
			
			// Create GEPs in caller for each value that we need.
			// Load SP first since we might need it.
			auto registers = getRegisterPtr(*caller);
			auto spPtr = targetInfo.getRegister(registers, *targetInfo.getStackPointer());
			spPtr->insertBefore(call);
			auto spValue = new LoadInst(spPtr, "sp", call);
			
			SmallVector<Value*, 8> arguments;
			for (const auto& vi : ci)
			{
				if (vi.type == ValueInformation::IntegerRegister)
				{
					auto registerPtr = targetInfo.getRegister(registers, *vi.registerInfo);
					registerPtr->insertBefore(call);
					auto registerValue = new LoadInst(registerPtr, vi.registerInfo->name, call);
					arguments.push_back(registerValue);
				}
				else if (vi.type == ValueInformation::Stack)
				{
					// assume one pointer-sized word
					auto offsetConstant = ConstantInt::get(integer, vi.frameBaseOffset);
					auto offset = BinaryOperator::Create(BinaryOperator::Add, spValue, offsetConstant, "", call);
					auto casted = new IntToPtrInst(offset, integerPtr, "", call);
					auto loaded = new LoadInst(casted, "", call);
					arguments.push_back(loaded);
				}
				else
				{
					llvm_unreachable("not implemented");
				}
			}
			
			// update AA
			CallInst* newCall = CallInst::Create(&newTarget, arguments, "", call);
			aa.replaceWithNewValue(call, newCall);
			
			// update call graph
			CallGraphNode* calleeNode = cg[caller];
			calleeNode->replaceCallEdge(cs, CallSite(newCall), newFuncNode);
			
			// replace call
			if (!call->use_empty())
			{
				call->replaceAllUsesWith(newCall);
				newCall->takeName(call);
			}
			call->eraseFromParent();
		}
	}
	
	Value* ArgumentRecovery::createReturnValue(Function &function, const CallInformation &ci, Instruction *insertionPoint)
	{
		TargetInfo& targetInfo = getAnalysis<TargetInfo>();
		
		if (ci.returns_size() == 1)
		{
			const auto& returnInfo = *ci.return_begin();
			if (returnInfo.type == ValueInformation::IntegerRegister)
			{
				auto gep = targetInfo.getRegister(registerPtr[&function], *returnInfo.registerInfo);
				gep->insertBefore(insertionPoint);
				return new LoadInst(gep, "", insertionPoint);
			}
			else
			{
				llvm_unreachable("not implemented");
			}
		}
		else
		{
			unsigned i = 0;
			Value* result = ConstantAggregateZero::get(function.getReturnType());
			for (const auto& returnInfo : ci.returns())
			{
				if (returnInfo.type == ValueInformation::IntegerRegister)
				{
					auto gep = targetInfo.getRegister(registerPtr[&function], *returnInfo.registerInfo);
					gep->insertBefore(insertionPoint);
					auto loaded = new LoadInst(gep, "", insertionPoint);
					result = InsertValueInst::Create(result, loaded, {i}, "set." + returnInfo.registerInfo->name, insertionPoint);
					i++;
				}
				else
				{
					llvm_unreachable("not implemented");
				}
			}
			return result;
		}
	}
	
	void ArgumentRecovery::updateFunctionBody(Function& oldFunction, Function& newFunction, const CallInformation &ci)
	{
		// Do not fix functions without a body.
		if (oldFunction.isDeclaration())
		{
			return;
		}
		
		LLVMContext& ctx = oldFunction.getContext();
		TargetInfo& targetInfo = getAnalysis<TargetInfo>();
		unsigned pointerSize = targetInfo.getPointerSize() * CHAR_BIT;
		Type* integer = Type::getIntNTy(ctx, pointerSize);
		Type* integerPtr = Type::getIntNPtrTy(ctx, pointerSize, 1);
		
		// (should this be moved to recoverArguments?)
		CallGraph& cg = getAnalysis<CallGraphWrapperPass>().getCallGraph();
		CallGraphNode* oldFuncNode = cg[&oldFunction];
		CallGraphNode* newFuncNode = cg.getOrInsertFunction(&newFunction);
		newFuncNode->stealCalledFunctionsFrom(oldFuncNode);
		
		// move code
		newFunction.getBasicBlockList().splice(newFunction.begin(), oldFunction.getBasicBlockList());
		
		// Create a register structure at the beginning of the function and copy arguments to it.
		Instruction* insertionPoint = newFunction.begin()->begin();
		Value* newRegisters = new AllocaInst(targetInfo.getRegisterStruct(), "registers", insertionPoint);
		oldFunction.arg_begin()->replaceAllUsesWith(newRegisters);
		registerPtr[&newFunction] = newRegisters;
		
		// get stack register from new set
		auto spPtr = targetInfo.getRegister(newRegisters, *targetInfo.getStackPointer());
		spPtr->insertBefore(insertionPoint);
		auto spValue = new LoadInst(spPtr, "sp", insertionPoint);
		
		// Copy each argument to the register structure or to the stack.
		auto valueIter = ci.begin();
		for (Argument& arg : newFunction.args())
		{
			if (valueIter->type == ValueInformation::IntegerRegister)
			{
				auto gep = targetInfo.getRegister(newRegisters, *valueIter->registerInfo);
				gep->insertBefore(insertionPoint);
				new StoreInst(&arg, gep, insertionPoint);
			}
			else if (valueIter->type == ValueInformation::Stack)
			{
				auto offsetConstant = ConstantInt::get(integer, valueIter->frameBaseOffset);
				auto offset = BinaryOperator::Create(BinaryOperator::Add, spValue, offsetConstant, "", insertionPoint);
				auto casted = new IntToPtrInst(offset, integerPtr, "", insertionPoint);
				new StoreInst(&arg, casted, insertionPoint);
			}
			else
			{
				llvm_unreachable("not implemented");
			}
			valueIter++;
		}
		
		// If the function returns, adjust return values.
		if (!newFunction.doesNotReturn() && ci.returns_size() > 0)
		{
			for (BasicBlock& bb : newFunction)
			{
				if (auto ret = dyn_cast<ReturnInst>(bb.getTerminator()))
				{
					Value* returnValue = createReturnValue(newFunction, ci, ret);
					ReturnInst::Create(ctx, returnValue, ret);
					ret->eraseFromParent();
				}
			}
		}
	}
	
	CallGraphNode* ArgumentRecovery::recoverArguments(CallGraphNode* node)
	{
		Function* fn = node->getFunction();
		if (fn == nullptr || !isRecoverable(*fn))
		{
			return nullptr;
		}
		
		ParameterRegistry& paramRegistry = getAnalysis<ParameterRegistry>();
		const CallInformation& callInfo = *paramRegistry.getCallInfo(*fn);
		
		Function& parameterized = createParameterizedFunction(*fn, callInfo);
		fixCallSites(*fn, parameterized, callInfo);
		updateFunctionBody(*fn, parameterized, callInfo);
		
		return getAnalysis<CallGraphWrapperPass>().getCallGraph().getOrInsertFunction(&parameterized);
	}
	
	char ArgumentRecovery::ID = 0;
}

CallGraphSCCPass* createArgumentRecoveryPass()
{
	return new ArgumentRecovery;
}

INITIALIZE_PASS_BEGIN(ArgumentRecovery, "argrec", "Argument Recovery", true, false)
INITIALIZE_PASS_DEPENDENCY(TargetInfo)
INITIALIZE_PASS_END(ArgumentRecovery, "argrec", "Argument Recovery", true, false)
