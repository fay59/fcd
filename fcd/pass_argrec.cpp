//
// pass_argrec.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "metadata.h"
#include "pass_argrec.h"
#include "passes.h"

#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/CallGraphSCCPass.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_os_ostream.h>

using namespace llvm;
using namespace std;

char ArgumentRecovery::ID = 0;

Value* ArgumentRecovery::getRegisterPtr(Function& fn)
{
	auto iter = registerPtr.find(&fn);
	if (iter != registerPtr.end())
	{
		return iter->second;
	}
	
	if (!md::areArgumentsRecoverable(fn))
	{
		return nullptr;
	}
	
	auto arg = &*fn.arg_begin();
	registerPtr[&fn] = arg;
	return arg;
}

void ArgumentRecovery::getAnalysisUsage(AnalysisUsage& au) const
{
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
		if (md::areArgumentsRecoverable(fn))
		{
			changed |= recoverArguments(fn);
		}
	}
	
	for (Function* toErase : functionsToErase)
	{
		toErase->eraseFromParent();
	}
	
	return changed;
}

Function& ArgumentRecovery::createParameterizedFunction(Function& base, const CallInformation& callInfo)
{
	Module& module = *base.getParent();
	auto info = TargetInfo::getTargetInfo(*base.getParent());
	SmallVector<string, 8> parameterNames;
	FunctionType* ft = createFunctionType(*info, callInfo, module, base.getName().str(), parameterNames);
	
	Function* newFunc = Function::Create(ft, base.getLinkage());
	base.getParent()->getFunctionList().insert(base.getIterator(), newFunc);
	
	newFunc->takeName(&base);
	newFunc->copyAttributesFrom(&base);
	md::copy(base, *newFunc);
	
	// set parameter names
	size_t i = 0;
	for (Argument& arg : newFunc->args())
	{
		arg.setName(parameterNames[i]);
		i++;
	}
	
	// set stack pointer
	i = 0;
	for (const auto& param : callInfo.parameters())
	{
		if (param.type == ValueInformation::IntegerRegister && param.registerInfo == info->getStackPointer())
		{
			md::setStackPointerArgument(*newFunc, static_cast<unsigned>(i));
			break;
		}
		++i;
	}
	
	return *newFunc;
}

void ArgumentRecovery::fixCallSites(Function& base, Function& newTarget, const CallInformation& ci)
{
	auto targetInfo = TargetInfo::getTargetInfo(*base.getParent());
	
	// loop over callers and transform call sites.
	while (!base.use_empty())
	{
		CallInst* call = cast<CallInst>(base.user_back());
		Function* caller = call->getParent()->getParent();
		auto registers = getRegisterPtr(*caller);
		auto newCall = createCallSite(*targetInfo, ci, newTarget, *registers, *call);
		
		// replace call
		newCall->takeName(call);
		call->eraseFromParent();
		
		md::incrementFunctionVersion(*caller);
	}
}

Value* ArgumentRecovery::createReturnValue(Function &function, const CallInformation &ci, Instruction *insertionPoint)
{
	assert(ci.returns_size() > 0);
	auto targetInfo = TargetInfo::getTargetInfo(*function.getParent());
	auto registers = getRegisterPtr(function);
	auto returnType = function.getReturnType();
	
	Value* result;
	if (ci.returns_size() == 1)
	{
		const auto& returnInfo = *ci.return_begin();
		auto gep = targetInfo->getRegister(registers, *returnInfo.registerInfo);
		gep->insertBefore(insertionPoint);
		result = new LoadInst(gep, "", insertionPoint);
		
		Type* gepElementType = cast<PointerType>(gep->getType())->getElementType();
		if (gepElementType != returnType)
		{
			if (returnType->isIntegerTy())
			{
				assert(gepElementType->isIntegerTy());
				assert(returnType->getIntegerBitWidth() < gepElementType->getIntegerBitWidth());
				result = new TruncInst(result, returnType, "", insertionPoint);
			}
			else if (returnType->isPointerTy())
			{
				assert(gepElementType->isIntegerTy());
				result = new IntToPtrInst(result, returnType, "", insertionPoint);
			}
			else
			{
				llvm_unreachable("Not implemented");
			}
		}
	}
	else
	{
		unsigned i = 0;
		result = ConstantAggregateZero::get(returnType);
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
	}
	return result;
}

void ArgumentRecovery::updateFunctionBody(Function& oldFunction, Function& newFunction, const CallInformation &ci)
{
	// Do not fix functions without a body.
	assert(!md::isPrototype(oldFunction));
	
	LLVMContext& ctx = oldFunction.getContext();
	auto targetInfo = TargetInfo::getTargetInfo(*oldFunction.getParent());
	unsigned pointerSize = targetInfo->getPointerSize() * CHAR_BIT;
	Type* integer = Type::getIntNTy(ctx, pointerSize);
	Type* integerPtr = Type::getIntNPtrTy(ctx, pointerSize, 1);
	
	// move code, delete leftover metadata on oldFunction
	newFunction.getBasicBlockList().splice(newFunction.begin(), oldFunction.getBasicBlockList());
	oldFunction.deleteBody();
	
	// Create a register structure at the beginning of the function and copy arguments to it.
	Argument* oldArg0 = &*oldFunction.arg_begin();
	Type* registerStruct = oldArg0->getType()->getPointerElementType();
	Instruction* insertionPoint = &*newFunction.begin()->begin();
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
	if (!newFunction.doesNotReturn() && !newFunction.getReturnType()->isVoidTy())
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

FunctionType* ArgumentRecovery::createFunctionType(TargetInfo &targetInfo, const CallInformation &ci, llvm::Module& module, const std::string& returnTypeName)
{
	SmallVector<string, 8> discarded;
	return createFunctionType(targetInfo, ci, module, returnTypeName, discarded);
}

FunctionType* ArgumentRecovery::createFunctionType(TargetInfo& info, const CallInformation& callInfo, llvm::Module& module, const std::string& returnTypeName, SmallVectorImpl<string>& parameterNames)
{
	LLVMContext& ctx = module.getContext();
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
	
	Type* returnType;
	if (returnTypes.size() == 0)
	{
		returnType = Type::getVoidTy(ctx);
	}
	else if (returnTypes.size() == 1)
	{
		returnType = returnTypes.front();
	}
	else
	{
		StructType* structTy = StructType::create(ctx);
		structTy->setBody(returnTypes);
		structTy->setName(returnTypeName);
		md::setRecoveredReturnFieldNames(module, *structTy, callInfo);
		returnType = structTy;
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
	ArrayRef<Type*> calleeParameterTypes = cast<FunctionType>(cast<PointerType>(callee.getType())->getElementType())->params();
	SmallVector<Value*, 8> arguments;
	for (const auto& vi : ci.parameters())
	{
		Value* argumentValue;
		if (vi.type == ValueInformation::IntegerRegister)
		{
			auto registerPtr = targetInfo.getRegister(&callerRegisters, *vi.registerInfo);
			registerPtr->insertBefore(&insertionPoint);
			argumentValue = new LoadInst(registerPtr, vi.registerInfo->name, &insertionPoint);
		}
		else if (vi.type == ValueInformation::Stack)
		{
			// assume one pointer-sized word
			auto offsetConstant = ConstantInt::get(integer, vi.frameBaseOffset);
			auto offset = BinaryOperator::Create(BinaryOperator::Add, spValue, offsetConstant, "", &insertionPoint);
			auto casted = new IntToPtrInst(offset, integerPtr, "", &insertionPoint);
			argumentValue = new LoadInst(casted, "", &insertionPoint);
		}
		else
		{
			llvm_unreachable("not implemented");
		}
		
		Type* expectedType = calleeParameterTypes[arguments.size()];
		if (expectedType != argumentValue->getType())
		{
			if (auto intTy = dyn_cast<IntegerType>(expectedType))
			{
				if (intTy->getBitWidth() < pointerSize)
				{
					argumentValue = new TruncInst(argumentValue, intTy, "", &insertionPoint);
				}
				else
				{
					llvm_unreachable("expecting larger integer than native register size!");
				}
			}
			else if (isa<PointerType>(expectedType))
			{
				argumentValue = new IntToPtrInst(argumentValue, expectedType, "", &insertionPoint);
			}
			else
			{
				llvm_unreachable("unsupported type conversion!");
			}
		}
		
		arguments.push_back(argumentValue);
	}
	
	CallInst* newCall = CallInst::Create(&callee, arguments, "", &insertionPoint);
	
	// Fix return value(s)
	unsigned i = 0;
	Instruction* returnInsertionPoint = newCall->getNextNode();
	for (const auto& vi : ci.returns())
	{
		if (vi.type == ValueInformation::IntegerRegister)
		{
			Value* registerValue = ci.returns_size() == 1
				? static_cast<Value*>(newCall)
				: ExtractValueInst::Create(newCall, {i}, vi.registerInfo->name, returnInsertionPoint);
			
			if (registerValue->getType() != integer)
			{
				if (auto intTy = dyn_cast<IntegerType>(registerValue->getType()))
				{
					if (intTy->getBitWidth() < pointerSize)
					{
						registerValue = new ZExtInst(registerValue, integer, "", returnInsertionPoint);
					}
					else
					{
						llvm_unreachable("received larger integer than native register size!");
					}
				}
				else if (isa<PointerType>(registerValue->getType()))
				{
					registerValue = new PtrToIntInst(registerValue, integer, "", returnInsertionPoint);
				}
				else
				{
					llvm_unreachable("unsupported type conversion!");
				}
			}
			
			auto registerPtr = targetInfo.getRegister(&callerRegisters, *vi.registerInfo);
			registerPtr->insertBefore(returnInsertionPoint);
			new StoreInst(registerValue, registerPtr, returnInsertionPoint);
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
	
	unique_ptr<CallInformation> uniqueCallInfo;
	const CallInformation* callInfo = nullptr;
	Function* parameterizedFunction = nullptr;
	if (Function* prototype = md::getFinalPrototype(fn))
	{
		callInfo = paramRegistry.getDefinitionCallInfo(*prototype);
		if (callInfo != nullptr)
		{
			parameterizedFunction = prototype;
			if (md::isPrototype(fn))
			{
				prototype->deleteBody();
			}
			
			parameterizedFunction->takeName(&fn);
			
			// Set stub parameter names.
			SmallVector<string, 8> parameterNames;
			auto& module = *prototype->getParent();
			auto info = TargetInfo::getTargetInfo(module);
			(void) createFunctionType(*info, *callInfo, module, fn.getName().str(), parameterNames);
			size_t paramIndex = 0;
			for (Argument& arg : parameterizedFunction->args())
			{
				assert(paramIndex < parameterNames.size());
				arg.setName(parameterNames[paramIndex]);
				++paramIndex;
			}
		}
	}
	
	if (callInfo == nullptr)
	{
		if (md::isPrototype(fn))
		{
			// find a call site and consider it canon
			for (auto user : fn.users())
			{
				if (auto call = dyn_cast<CallInst>(user))
				{
					uniqueCallInfo = paramRegistry.analyzeCallSite(CallSite(call));
					callInfo = uniqueCallInfo.get();
					break;
				}
			}
		}
		else
		{
			callInfo = paramRegistry.getCallInfo(fn);
		}
		parameterizedFunction = &createParameterizedFunction(fn, *callInfo);
	}
	
	if (callInfo != nullptr)
	{
		fixCallSites(fn, *parameterizedFunction, *callInfo);
		
		if (!md::isPrototype(fn))
		{
			updateFunctionBody(fn, *parameterizedFunction, *callInfo);
			functionsToErase.push_back(&fn);
		}
		return true;
	}
	return false;
}

ModulePass* createArgumentRecoveryPass()
{
	return new ArgumentRecovery;
}

INITIALIZE_PASS_BEGIN(ArgumentRecovery, "argrec", "Argument Recovery", true, false)
INITIALIZE_PASS_END(ArgumentRecovery, "argrec", "Argument Recovery", true, false)
