//
// metadata.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "metadata.h"

using namespace llvm;
using namespace std;

namespace
{
	template<typename T>
	void setFlag(T& value, const char* flag)
	{
		auto& ctx = value.getContext();
		Type* i1 = Type::getInt1Ty(ctx);
		MDNode* zeroNode = MDNode::get(ctx, ConstantAsMetadata::get(ConstantInt::get(i1, 1)));
		value.setMetadata(flag, zeroNode);
	}
	
	bool getMdNameForType(const StructType& type, string& output)
	{
		if (type.hasName())
		{
			StringRef typeName = type.getName();
			output = typeName.str() + ".fcd.fields";
			return true;
		}
		return false;
	}
}

void md::ensureFunctionBody(Function& fn)
{
	assert(fn.getParent() != nullptr);
	if (fn.isDeclaration())
	{
		LLVMContext& ctx = fn.getContext();
		Function* placeholder = Function::Create(fn.getFunctionType(), GlobalValue::ExternalWeakLinkage, "fcd.placeholder", fn.getParent());
		BasicBlock* body = BasicBlock::Create(ctx, "", &fn);
		SmallVector<Value*, 4> args;
		for (Argument& arg : fn.args())
		{
			args.push_back(&arg);
		}
		
		auto callResult = CallInst::Create(placeholder, args, "", body);
		ReturnInst::Create(ctx, fn.getReturnType()->isVoidTy() ? nullptr : callResult, body);
	}
}

vector<string> md::getIncludedFiles(Module& module)
{
	vector<string> result;
	if (MDNode* node = dyn_cast_or_null<MDNode>(module.getModuleFlag("fcd.includes")))
	{
		for (Metadata* op : node->operands())
		{
			if (auto file = dyn_cast<MDString>(op))
			{
				result.push_back(file->getString());
			}
		}
	}
	return result;
}

ConstantInt* md::getStackPointerArgument(const Function &fn)
{
	if (auto node = fn.getMetadata("fcd.stackptr"))
	{
		if (auto constant = dyn_cast<ConstantAsMetadata>(node->getOperand(0)))
		{
			return dyn_cast<ConstantInt>(constant->getValue());
		}
	}
	return nullptr;
}

ConstantInt* md::getVirtualAddress(const Function& fn)
{
	if (auto node = fn.getMetadata("fcd.vaddr"))
	{
		if (auto constantMD = dyn_cast<ConstantAsMetadata>(node->getOperand(0)))
		{
			if (auto constantInt = dyn_cast<ConstantInt>(constantMD->getValue()))
			{
				return constantInt;
			}
		}
	}
	return nullptr;
}

unsigned md::getFunctionVersion(const Function& fn)
{
	if (auto node = fn.getMetadata("fcd.funver"))
	{
		if (auto constantMD = dyn_cast<ConstantAsMetadata>(node->getOperand(0)))
		{
			if (auto constantInt = dyn_cast<ConstantInt>(constantMD->getValue()))
			{
				return static_cast<unsigned>(constantInt->getLimitedValue());
			}
		}
	}
	return 0;
}

Function* md::getFinalPrototype(const Function& fn)
{
	if (auto node = fn.getMetadata("fcd.prototype"))
	{
		if (auto valueAsMd = dyn_cast<ValueAsMetadata>(node->getOperand(0)))
		{
			return cast<Function>(valueAsMd->getValue());
		}
	}
	return nullptr;
}

bool md::isStub(const Function &fn)
{
	return fn.getMetadata("fcd.stub") != nullptr;
}

bool md::areArgumentsExact(const Function &fn)
{
	return fn.getMetadata("fcd.exact.args") != nullptr;
}

bool md::areArgumentsRecoverable(const Function &fn)
{
	return fn.getMetadata("fcd.recoverable") != nullptr;
}

bool md::isPrototype(const Function &fn)
{
	if (fn.isDeclaration() || md::isStub(fn))
	{
		return true;
	}
	
	// check if it only calls a fcd.placeholder function
	if (fn.getBasicBlockList().size() == 1)
	{
		const BasicBlock& entry = fn.getEntryBlock();
		if (entry.getInstList().size() == 2)
		if (const CallInst* call = dyn_cast<CallInst>(entry.begin()))
		if (Function* fn = call->getCalledFunction())
		{
			return fn->getName().startswith("fcd.placeholder");
		}
	}
	
	return false;
}

bool md::isProgramMemory(const Instruction &value)
{
	return value.getMetadata("fcd.prgmem") != nullptr;
}

MDString* md::getAssemblyString(const Function& fn)
{
	if (auto node = fn.getMetadata("fcd.asm"))
	{
		if (auto nameNode = dyn_cast<MDString>(node->getOperand(0)))
		{
			return nameNode;
		}
	}
	return nullptr;
}

void md::addIncludedFiles(Module& module, const vector<string>& includedFiles)
{
	LLVMContext& ctx = module.getContext();
	SmallVector<Metadata*, 20> mdIncludes;
	for (const auto& file : includedFiles)
	{
		mdIncludes.push_back(MDString::get(ctx, file));
	}
	module.addModuleFlag(Module::AppendUnique, "fcd.includes", MDNode::get(ctx, mdIncludes));
}

void md::setVirtualAddress(Function& fn, uint64_t virtualAddress)
{
	ensureFunctionBody(fn);
	auto& ctx = fn.getContext();
	ConstantInt* cvaddr = ConstantInt::get(Type::getInt64Ty(ctx), virtualAddress);
	MDNode* vaddrNode = MDNode::get(ctx, ConstantAsMetadata::get(cvaddr));
	fn.setMetadata("fcd.vaddr", vaddrNode);
}

void md::incrementFunctionVersion(llvm::Function &fn)
{
	unsigned newVersion = getFunctionVersion(fn) + 1;
	auto& ctx = fn.getContext();
	ConstantInt* cNewVersion = ConstantInt::get(Type::getInt32Ty(ctx), newVersion);
	MDNode* versionNode = MDNode::get(ctx, ConstantAsMetadata::get(cNewVersion));
	fn.setMetadata("fcd.funver", versionNode);
}

void md::setFinalPrototype(Function& stub, Function& target)
{
	ensureFunctionBody(stub);
	ensureFunctionBody(target);
	stub.setMetadata("fcd.prototype", MDNode::get(stub.getContext(), ValueAsMetadata::get(&target)));
}

void md::setIsStub(Function &fn, bool stub)
{
	ensureFunctionBody(fn);
	if (stub)
	{
		setFlag(fn, "fcd.stub");
	}
	else
	{
		fn.setMetadata("fcd.stub", nullptr);
	}
}

void md::setArgumentsExact(Function &fn, bool exact)
{
	ensureFunctionBody(fn);
	if (exact)
	{
		setFlag(fn, "fcd.exact.args");
	}
	else
	{
		fn.setMetadata("fcd.exact.args", nullptr);
	}
}

void md::setArgumentsRecoverable(Function &fn, bool recoverable)
{
	ensureFunctionBody(fn);
	if (recoverable)
	{
		setFlag(fn, "fcd.recoverable");
	}
	else
	{
		fn.setMetadata("fcd.recoverable", nullptr);
	}
}

void md::setStackPointerArgument(Function &fn, unsigned int argIndex)
{
	ensureFunctionBody(fn);
	auto& ctx = fn.getContext();
	ConstantInt* cArgIndex = ConstantInt::get(Type::getInt32Ty(ctx), argIndex);
	MDNode* argIndexNode = MDNode::get(ctx, ConstantAsMetadata::get(cArgIndex));
	fn.setMetadata("fcd.stackptr", argIndexNode);
}

void md::removeStackPointerArgument(Function& fn)
{
	ensureFunctionBody(fn);
	fn.setMetadata("fcd.stackptr", nullptr);
}

void md::setAssemblyString(Function &fn, StringRef assembly)
{
	ensureFunctionBody(fn);
	LLVMContext& ctx = fn.getContext();
	MDNode* asmNode = MDNode::get(ctx, MDString::get(ctx, assembly));
	fn.setMetadata("fcd.asm", asmNode);
}

void md::setStackFrame(AllocaInst &alloca)
{
	setFlag(alloca, "fcd.stackframe");
}

void md::setProgramMemory(Instruction &value, bool isProgramMemory)
{
	if (isProgramMemory)
	{
		if (!md::isProgramMemory(value))
		{
			setFlag(value, "fcd.prgmem");
		}
	}
	else if (md::isProgramMemory(value))
	{
		value.setMetadata("fcd.prgmem", nullptr);
	}
}

void md::copy(const Function& from, Function& to)
{
	if (auto ptr = getStackPointerArgument(from))
	{
		setStackPointerArgument(to, static_cast<unsigned>(ptr->getLimitedValue()));
	}
	if (auto address = getVirtualAddress(from))
	{
		setVirtualAddress(to, address->getLimitedValue());
	}
	if (auto target = getFinalPrototype(from))
	{
		setFinalPrototype(to, *target);
	}
	if (areArgumentsRecoverable(from))
	{
		setArgumentsRecoverable(to);
	}
}

bool md::isRegisterStruct(const Value &value)
{
	if (auto arg = dyn_cast<Argument>(&value))
	{
		const Function& fn = *arg->getParent();
		return areArgumentsRecoverable(fn) && arg == &*fn.arg_begin();
	}
	
	if (auto alloca = dyn_cast<AllocaInst>(&value))
	{
		return alloca->getMetadata("fcd.registers") != nullptr;
	}
	
	return false;
}

void md::setRegisterStruct(AllocaInst& alloca, bool registerStruct)
{
	auto currentNode = alloca.getMetadata("fcd.registers");
	if (registerStruct)
	{
		if (currentNode == nullptr)
		{
			setFlag(alloca, "fcd.registers");
		}
	}
	else if (currentNode != nullptr)
	{
		alloca.setMetadata("fcd.registers", nullptr);
	}
}

void md::setRecoveredReturnFieldNames(Module& module, StructType& returnType, const CallInformation& callInfo)
{
	LLVMContext& ctx = module.getContext();
	
	string key;
	bool result = getMdNameForType(returnType, key);
	assert(result); (void) result;
	
	auto mdNode = module.getOrInsertNamedMetadata(key);
	for (const ValueInformation& vi : callInfo.returns())
	{
		MDString* operand = nullptr;
		if (vi.type == ValueInformation::IntegerRegister)
		{
			operand = MDString::get(ctx, vi.registerInfo->name);
		}
		else if (vi.type == ValueInformation::Stack)
		{
			string fieldName;
			raw_string_ostream(fieldName) << "sp" << vi.frameBaseOffset;
			operand = MDString::get(ctx, fieldName);
		}
		else
		{
			llvm_unreachable("not implemented");
		}
		mdNode->addOperand(MDNode::get(ctx, operand));
	}
}

StringRef md::getRecoveredReturnFieldName(Module& module, StructType& returnType, unsigned int i)
{
	string key;
	if (getMdNameForType(returnType, key))
	{
		if (auto mdNode = module.getNamedMetadata(key))
		{
			if (i < mdNode->getNumOperands())
			{
				return cast<MDString>(mdNode->getOperand(i)->getOperand(0))->getString();
			}
		}
	}
	
	return "";
}
