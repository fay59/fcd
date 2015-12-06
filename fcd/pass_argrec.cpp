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

#include "metadata.h"
#include "pass_argrec.h"
#include "passes.h"

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

char ArgumentRecovery::ID = 0;

bool ArgumentRecovery::isRecoverable(Function& fn)
{
	return md::getVirtualAddress(fn) != nullptr && !md::hasRecoveredArguments(fn);
}

Value* ArgumentRecovery::getRegisterPtr(Function& fn)
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

void ArgumentRecovery::getAnalysisUsage(AnalysisUsage& au) const
{
	au.addRequired<AliasAnalysis>();
	au.addRequired<CallGraphWrapperPass>();
	au.addRequired<ParameterRegistry>();
	ModulePass::getAnalysisUsage(au);
}

bool ArgumentRecovery::runOnModule(Module& module)
{
	for (Function& fn : module.getFunctionList())
	{
		getRegisterPtr(fn);
	}
	
	bool changed = false;
	for (Function& fn : module.getFunctionList())
	{
		if (isRecoverable(fn))
		{
			changed |= recoverArguments(fn);
		}
	}
	return changed;
}

Function& ArgumentRecovery::createParameterizedFunction(Function& base, const CallInformation& callInfo)
{
	LLVMContext& ctx = base.getContext();
	auto info = TargetInfo::getTargetInfo(*base.getParent());
	SmallVector<string, 8> parameterNames;
	string returnTypeName = (base.getName() + ".return").str();
	FunctionType* ft = createFunctionType(*info, ctx, callInfo, returnTypeName, parameterNames);
	
	Function* newFunc = Function::Create(ft, base.getLinkage());
	newFunc->copyAttributesFrom(&base);
	md::setRecoveredArguments(*newFunc);
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
	auto targetInfo = TargetInfo::getTargetInfo(*base.getParent());
	AliasAnalysis& aa = getAnalysis<AliasAnalysis>();
	CallGraph& cg = getAnalysis<CallGraphWrapperPass>().getCallGraph();
	
	CallGraphNode* newFuncNode = cg.getOrInsertFunction(&newTarget);
	
	// loop over callers and transform call sites.
	while (!base.use_empty())
	{
		CallInst* call = cast<CallInst>(base.user_back());
		Function* caller = call->getParent()->getParent();
		auto registers = getRegisterPtr(*caller);
		auto newCall = createCallSite(*targetInfo, ci, newTarget, *registers, *call);
		
		// update AA, call graph
		aa.replaceWithNewValue(call, newCall);
		cg[caller]->replaceCallEdge(CallSite(call), CallSite(newCall), newFuncNode);
		
		// replace call
		newCall->takeName(call);
		call->eraseFromParent();
	}
}

Value* ArgumentRecovery::createReturnValue(Function &function, const CallInformation &ci, Instruction *insertionPoint)
{
	auto targetInfo = TargetInfo::getTargetInfo(*function.getParent());
	auto registers = getRegisterPtr(function);
	
	unsigned i = 0;
	Value* result = ConstantAggregateZero::get(function.getReturnType());
	for (const auto& returnInfo : ci.returns())
	{
		if (returnInfo.type == ValueInformation::IntegerRegister)
		{
			auto gep = targetInfo->getRegister(registers, *returnInfo.registerInfo);
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

void ArgumentRecovery::updateFunctionBody(Function& oldFunction, Function& newFunction, const CallInformation &ci)
{
	// Do not fix functions without a body.
	if (oldFunction.isDeclaration())
	{
		return;
	}
	
	LLVMContext& ctx = oldFunction.getContext();
	auto targetInfo = TargetInfo::getTargetInfo(*oldFunction.getParent());
	unsigned pointerSize = targetInfo->getPointerSize() * CHAR_BIT;
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
	Argument* oldArg0 = oldFunction.arg_begin();
	Type* registerStruct = oldArg0->getType()->getPointerElementType();
	Instruction* insertionPoint = newFunction.begin()->begin();
	AllocaInst* newRegisters = new AllocaInst(registerStruct, "registers", insertionPoint);
	md::setRegisterStruct(*newRegisters);
	oldArg0->replaceAllUsesWith(newRegisters);
	registerPtr[&newFunction] = newRegisters;
	
	// get stack register from new set
	auto spPtr = targetInfo->getRegister(newRegisters, *targetInfo->getStackPointer());
	spPtr->insertBefore(insertionPoint);
	auto spValue = new LoadInst(spPtr, "sp", insertionPoint);
	
	// Copy each argument to the register structure or to the stack.
	auto valueIter = ci.begin();
	for (Argument& arg : newFunction.args())
	{
		if (valueIter->type == ValueInformation::IntegerRegister)
		{
			auto gep = targetInfo->getRegister(newRegisters, *valueIter->registerInfo);
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

FunctionType* ArgumentRecovery::createFunctionType(TargetInfo &targetInfo, LLVMContext &ctx, const CallInformation &ci, StringRef returnTypeName)
{
	SmallVector<string, 8> parameterNames;
	return createFunctionType(targetInfo, ctx, ci, returnTypeName, parameterNames);
}

FunctionType* ArgumentRecovery::createFunctionType(TargetInfo& info, LLVMContext& ctx, const CallInformation& callInfo, StringRef returnTypeName, SmallVectorImpl<string>& parameterNames)
{
	Type* integer = Type::getIntNTy(ctx, info.getPointerSize() * CHAR_BIT);
	
	SmallVector<Type*, 8> parameterTypes;
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
		
		returnType = StructType::create(returnTypes, returnTypeName);
	}
	
	assert(!callInfo.isVararg() && "not implemented");
	return FunctionType::get(returnType, parameterTypes, false);
}

CallInst* ArgumentRecovery::createCallSite(TargetInfo& targetInfo, const CallInformation& ci, Value& callee, Value& callerRegisters, Instruction& insertionPoint)
{
	LLVMContext& ctx = insertionPoint.getContext();
	
	unsigned pointerSize = targetInfo.getPointerSize() * CHAR_BIT;
	Type* integer = Type::getIntNTy(ctx, pointerSize);
	Type* integerPtr = Type::getIntNPtrTy(ctx, pointerSize, 1);
	
	// Create GEPs in caller for each value that we need.
	// Load SP first since we might need it.
	auto spPtr = targetInfo.getRegister(&callerRegisters, *targetInfo.getStackPointer());
	spPtr->insertBefore(&insertionPoint);
	auto spValue = new LoadInst(spPtr, "sp", &insertionPoint);
	
	// Fix parameters
	SmallVector<Value*, 8> arguments;
	for (const auto& vi : ci.parameters())
	{
		if (vi.type == ValueInformation::IntegerRegister)
		{
			auto registerPtr = targetInfo.getRegister(&callerRegisters, *vi.registerInfo);
			registerPtr->insertBefore(&insertionPoint);
			auto registerValue = new LoadInst(registerPtr, vi.registerInfo->name, &insertionPoint);
			arguments.push_back(registerValue);
		}
		else if (vi.type == ValueInformation::Stack)
		{
			// assume one pointer-sized word
			auto offsetConstant = ConstantInt::get(integer, vi.frameBaseOffset);
			auto offset = BinaryOperator::Create(BinaryOperator::Add, spValue, offsetConstant, "", &insertionPoint);
			auto casted = new IntToPtrInst(offset, integerPtr, "", &insertionPoint);
			auto loaded = new LoadInst(casted, "", &insertionPoint);
			arguments.push_back(loaded);
		}
		else
		{
			llvm_unreachable("not implemented");
		}
	}
	
	CallInst* newCall = CallInst::Create(&callee, arguments, "", &insertionPoint);
	
	// Fix return value(s)
	unsigned i = 0;
	Instruction* returnInsertionPoint = newCall->getNextNode();
	for (const auto& vi : ci.returns())
	{
		if (vi.type == ValueInformation::IntegerRegister)
		{
			auto registerField = ExtractValueInst::Create(newCall, {i}, vi.registerInfo->name, returnInsertionPoint);
			auto registerPtr = targetInfo.getRegister(&callerRegisters, *vi.registerInfo);
			registerPtr->insertBefore(returnInsertionPoint);
			new StoreInst(registerField, registerPtr, returnInsertionPoint);
		}
		else
		{
			llvm_unreachable("not implemented");
		}
		i++;
	}
	
	return newCall;
}

bool ArgumentRecovery::recoverArguments(Function& fn)
{
	ParameterRegistry& paramRegistry = getAnalysis<ParameterRegistry>();
	const CallInformation& callInfo = *paramRegistry.getCallInfo(fn);
	
	Function& parameterized = createParameterizedFunction(fn, callInfo);
	fixCallSites(fn, parameterized, callInfo);
	updateFunctionBody(fn, parameterized, callInfo);
	
	return getAnalysis<CallGraphWrapperPass>().getCallGraph().getOrInsertFunction(&parameterized);
}

ModulePass* createArgumentRecoveryPass()
{
	return new ArgumentRecovery;
}

INITIALIZE_PASS_BEGIN(ArgumentRecovery, "argrec", "Argument Recovery", true, false)
INITIALIZE_PASS_END(ArgumentRecovery, "argrec", "Argument Recovery", true, false)
