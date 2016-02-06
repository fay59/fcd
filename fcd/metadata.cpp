//
// metadata.cpp
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

using namespace llvm;
using namespace std;

namespace
{
	template<typename T>
	void setFlag(T& value, const char* flag)
	{
		auto& ctx = value.getContext();
		Type* i1 = Type::getInt1Ty(ctx);
		MDNode* zeroNode = MDNode::get(ctx, ConstantAsMetadata::get(ConstantInt::getNullValue(i1)));
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
	
	void ensureFunctionBody(Function& fn)
	{
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
			
			md::setPrototype(fn);
		}
	}
}

ConstantInt* md::getStackPointerArgument(const Function &fn)
{
	if (auto node = fn.getMetadata("fcd.stackptr"))
	if (auto constant = dyn_cast<ConstantAsMetadata>(node->getOperand(0)))
	{
		return dyn_cast<ConstantInt>(constant->getValue());
	}
	return nullptr;
}

ConstantInt* md::getVirtualAddress(const Function& fn)
{
	if (auto node = fn.getMetadata("fcd.vaddr"))
	if (auto constantMD = dyn_cast<ConstantAsMetadata>(node->getOperand(0)))
	if (auto constantInt = dyn_cast<ConstantInt>(constantMD->getValue()))
	{
		return constantInt;
	}
	return nullptr;
}

MDString* md::getImportName(const Function& fn)
{
	if (auto node = fn.getMetadata("fcd.importname"))
	if (auto nameNode = dyn_cast<MDString>(node->getOperand(0)))
	{
		return nameNode;
	}
	return nullptr;
}

bool md::hasRecoveredArguments(const Function &fn)
{
	return fn.getMetadata("fcd.recovered") != nullptr;
}

bool md::isPrototype(const Function &fn)
{
	return fn.isDeclaration() || fn.getMetadata("fcd.prototype") != nullptr || fn.getMetadata("fcd.importname") != nullptr;
}

bool md::isStackFrame(const AllocaInst &alloca)
{
	return alloca.getMetadata("fcd.stackframe") != nullptr;
}

bool md::isProgramMemory(const Instruction &value)
{
	return value.getMetadata("fcd.prgmem") != nullptr;
}

bool md::isNonInlineReturn(const ReturnInst &ret)
{
	return ret.getMetadata("fcd.realret") != nullptr;
}

MDString* md::getAssemblyString(const Function& fn)
{
	if (auto node = fn.getMetadata("fcd.asm"))
	if (auto nameNode = dyn_cast<MDString>(node->getOperand(0)))
	{
		return nameNode;
	}
	return nullptr;
}

void md::setVirtualAddress(Function& fn, uint64_t virtualAddress)
{
	ensureFunctionBody(fn);
	auto& ctx = fn.getContext();
	ConstantInt* cvaddr = ConstantInt::get(Type::getInt64Ty(ctx), virtualAddress);
	MDNode* vaddrNode = MDNode::get(ctx, ConstantAsMetadata::get(cvaddr));
	fn.setMetadata("fcd.vaddr", vaddrNode);
}

void md::setImportName(Function& fn, StringRef name)
{
	ensureFunctionBody(fn);
	auto& ctx = fn.getContext();
	MDNode* nameNode = MDNode::get(ctx, MDString::get(ctx, name));
	fn.setMetadata("fcd.importname", nameNode);
}

void md::setRecoveredArguments(Function &fn)
{
	ensureFunctionBody(fn);
	setFlag(fn, "fcd.recovered");
}

void md::setPrototype(Function &fn, bool prototype)
{
	if (fn.isDeclaration())
	{
		ensureFunctionBody(fn);
	}
	else if (!isPrototype(fn) && prototype)
	{
		setFlag(fn, "fcd.prototype");
	}
	else if (isPrototype(fn) && !prototype)
	{
		fn.setMetadata("fcd.prototype", nullptr);
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

void md::setNonInlineReturn(ReturnInst& ret)
{
	setFlag(ret, "fcd.realret");
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
	if (auto name = getImportName(from))
	{
		setImportName(to, name->getString());
	}
	if (hasRecoveredArguments(from))
	{
		setRecoveredArguments(to);
	}
	if (isPrototype(from))
	{
		setPrototype(to);
	}
}

bool md::isRegisterStruct(const Value &value)
{
	if (auto arg = dyn_cast<Argument>(&value))
	{
		const Function& fn = *arg->getParent();
		return !hasRecoveredArguments(fn) && arg == fn.arg_begin();
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
	assert(result);
	
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
	if (auto mdNode = module.getNamedMetadata(key))
	if (i < mdNode->getNumOperands())
	{
		return cast<MDString>(mdNode->getOperand(i)->getOperand(0))->getString();
	}
	
	return "";
}
