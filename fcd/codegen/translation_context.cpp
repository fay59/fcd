//
// translation_context.cpp
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
#include "not_null.h"
#include "params_registry.h"
#include "translation_context.h"
#include "x86_register_map.h"

#include <llvm/ADT/Triple.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include <array>
#include <unordered_set>
#include <vector>

using namespace llvm;
using namespace std;

namespace
{
	cs_mode cs_size_mode(size_t address_size)
	{
		switch (address_size)
		{
			case 2: return CS_MODE_16;
			case 4: return CS_MODE_32;
			case 8: return CS_MODE_64;
			default:
				llvm_unreachable("invalid pointer size");
		}
	}
	
	CallInformation infoForInstruction(TargetInfo& target, const cs_insn& inst)
	{
		const cs_detail& detail = *inst.detail;
		CallInformation result;
		
		// setStage isn't really useful here since there won't be any recursive analysis
		// that could benefit from knowing if this object is currently being updated or not,
		// but it's not a bad thing to set it either.
		result.setStage(CallInformation::Analyzing);
		
		// inputs
		for (size_t i = 0; i < detail.regs_read_count; ++i)
		{
			if (auto registerInfo = target.registerInfo(detail.regs_read[i]))
			{
				const auto& largest = target.largestOverlappingRegister(*registerInfo);
				result.addParameter(ValueInformation::IntegerRegister, &largest);
			}
		}
		
		// outputs
		for (size_t i = 0; i < detail.regs_write_count; ++i)
		{
			if (auto registerInfo = target.registerInfo(detail.regs_write[i]))
			{
				const auto& largest = target.largestOverlappingRegister(*registerInfo);
				result.addReturn(ValueInformation::IntegerRegister, &largest);
			}
		}
		
		result.setStage(CallInformation::Completed);
		return result;
	}
	
	void createAsmCall(TargetInfo& targetInfo, const cs_insn& inst, Value* registerStruct, BasicBlock& insertInto)
	{
		Module& module = *insertInto.getParent()->getParent();
		LLVMContext& ctx = module.getContext();
		Type* integer = Type::getIntNTy(ctx, targetInfo.getPointerSize() * CHAR_BIT);
		CallInformation info = infoForInstruction(targetInfo, inst);
		
		// Create a return type structure
		StructType* returnType = StructType::create(module.getContext(), string(inst.mnemonic) + ".return");
		// XXX: this assumes that we only deal with integer registers (which may have to be updated shortly)
		
		unordered_map<unsigned, GetElementPtrInst*> gepsForRegister;
		
		size_t i = 0;
		vector<Type*> structBody(info.returns_size());
		for (ValueInformation& value : info.returns())
		{
			assert(value.type == ValueInformation::IntegerRegister);
			structBody[i] = integer;
			
			GetElementPtrInst*& gep = gepsForRegister[value.registerInfo->registerId];
			if (gep == nullptr)
			{
				gep = targetInfo.getRegister(registerStruct, *value.registerInfo);
				insertInto.getInstList().push_back(gep);
			}
			++i;
		}
		
		returnType->setBody(structBody);
		md::setRecoveredReturnFieldNames(module, *returnType, info);
		
		// Create a function type for the assembly value
		// XXX: this also assumes that we only deal with integer registers
		vector<Type*> parameters(info.parameters_size());
		i = 0;
		for (ValueInformation& value : info.parameters())
		{
			assert(value.type == ValueInformation::IntegerRegister);
			parameters[i] = integer;
			
			GetElementPtrInst*& gep = gepsForRegister[value.registerInfo->registerId];
			if (gep == nullptr)
			{
				gep = targetInfo.getRegister(registerStruct, *value.registerInfo);
				insertInto.getInstList().push_back(gep);
			}
			++i;
		}
		
		string disassembly;
		raw_string_ostream(disassembly) << inst.mnemonic << ' ' << inst.op_str;
		FunctionType* ft = FunctionType::get(returnType, parameters, false);
		Function* asmFunc = Function::Create(ft, GlobalValue::ExternalLinkage, "fcd.asm", &module);
		md::setAssemblyString(*asmFunc, disassembly);
		
		// set parameter names while we're at it
		auto argIter = asmFunc->arg_begin();
		for (ValueInformation& value : info.parameters())
		{
			argIter->setName(value.registerInfo->name);
			++argIter;
		}
		
		SmallVector<Value*, 16> paramValues;
		for (ValueInformation& value : info.parameters())
		{
			auto load = new LoadInst(gepsForRegister[value.registerInfo->registerId], value.registerInfo->name, &insertInto);
			paramValues.push_back(load);
		}
		auto asmCall = CallInst::Create(asmFunc, paramValues, "", &insertInto);
		
		i = 0;
		for (ValueInformation& value : info.returns())
		{
			auto element = ExtractValueInst::Create(asmCall, {static_cast<unsigned>(i)}, value.registerInfo->name, &insertInto);
			new StoreInst(element, gepsForRegister[value.registerInfo->registerId], &insertInto);
			++i;
		}
	}
}

TranslationContext::TranslationContext(LLVMContext& context, Executable& executable, const x86_config& config, const std::string& module_name)
: context(context)
, executable(executable)
, module(new Module(module_name, context))
{
	if (auto generator = CodeGenerator::x86(context))
	{
		irgen = move(generator);
	}
	else
	{
		// This is REALLY not supposed to happen. The parameters are static.
		// XXX: If/when we have other architectures, change this to something non-fatal.
		errs() << "couldn't create IR generation module";
		abort();
	}
	
	auto options = static_cast<unsigned>(CS_MODE_LITTLE_ENDIAN | cs_size_mode(config.address_size));
	if (auto csHandle = capstone::create(CS_ARCH_X86, options))
	{
		cs.reset(new capstone(move(csHandle.get())));
	}
	else
	{
		errs() << "couldn't open Capstone handle: " << csHandle.getError().message() << '\n';
		abort();
	}
	
	resultFnTy = FunctionType::get(Type::getVoidTy(context), { irgen->getRegisterTy()->getPointerTo() }, false);
	functionMap.reset(new AddressToFunction(*module, *resultFnTy));
	
	Type* int32Ty = Type::getInt32Ty(context);
	Type* int64Ty = Type::getInt64Ty(context);
	StructType* configTy = irgen->getConfigTy();
	Constant* configConstant = ConstantStruct::get(configTy,
		ConstantInt::get(int32Ty, config.isa),
		ConstantInt::get(int64Ty, config.address_size),
		ConstantInt::get(int32Ty, config.ip),
		ConstantInt::get(int32Ty, config.sp),
		ConstantInt::get(int32Ty, config.fp),
		nullptr);

	configVariable = new GlobalVariable(*module, configTy, true, GlobalVariable::PrivateLinkage, configConstant, "config");
	
	string dataLayout;
	Triple triple(executable.getTargetTriple());
	
	if (triple.getOS() == Triple::Linux)
	{
		dataLayout += "m:";
	}
	
	// endianness (little)
	dataLayout += "e-";
	
	// native integer types (at least 8 and 16 bytes; very often 32; often 64)
	dataLayout += "n8:16";
	if (config.isa >= x86_isa32)
	{
		dataLayout += ":32";
	}
	if (config.isa >= x86_isa64)
	{
		dataLayout += ":64";
	}
	dataLayout += "-";
	
	// Pointer size
	// Irrelevant for address space 0, since this is the register address space and these pointers are never stored
	// to memory.
	dataLayout += "p0:64:64:64-";
	
	// address space 1 (memory address space)
	char addressSize[] = ":512";
	snprintf(addressSize, sizeof addressSize, ":%zu", config.address_size * 8);
	dataLayout += string("p1") + addressSize + addressSize + addressSize;
	
	module->setDataLayout(dataLayout);
	module->setTargetTriple(triple.str());
}

TranslationContext::~TranslationContext()
{
}

void TranslationContext::setFunctionName(uint64_t address, const std::string &name)
{
	functionMap->getCallTarget(address)->setName(name);
}

Function* TranslationContext::createFunction(uint64_t baseAddress)
{
	Function* fn = functionMap->createFunction(baseAddress);
	assert(fn != nullptr);
	
	auto targetInfo = TargetInfo::getTargetInfo(*module);
	AddressToBlock blockMap(*fn);
	BasicBlock* entry = &fn->back();
	
	Argument* registers = static_cast<Argument*>(fn->arg_begin());
	auto flags = new AllocaInst(irgen->getFlagsTy(), "flags", entry);
	
	ArrayRef<Value*> ipGepIndices = irgen->getIpOffset();
	auto ipPointer = GetElementPtrInst::CreateInBounds(registers, ipGepIndices, "", entry);
	Type* ipType = GetElementPtrInst::getIndexedType(irgen->getRegisterTy(), ipGepIndices);
	
	Function* prologue = irgen->implementationForPrologue();
	irgen->inlineFunction(fn, prologue, { configVariable, registers }, *functionMap, blockMap, baseAddress);
	
	uint64_t addressToDisassemble;
	auto end = executable.end();
	auto inst = cs->alloc();
	SmallVector<Value*, 4> inliningParameters = { configVariable, nullptr, registers, flags };
	while (blockMap.getOneStub(addressToDisassemble))
	{
		if (auto begin = executable.map(addressToDisassemble))
		if (cs->disassemble(inst.get(), begin, end, addressToDisassemble))
		if (BasicBlock* thisBlock = blockMap.implementInstruction(inst->address)) // already implemented?
		{
			// store instruction pointer
			// (this needs to be the IP of the next instruction)
			auto nextInstAddress = inst->address + inst->size;
			auto ipValue = ConstantInt::get(ipType, nextInstAddress);
			new StoreInst(ipValue, ipPointer, false, thisBlock);
			
			if (Function* implementation = irgen->implementationFor(inst->id))
			{
				// We have an implementation: inline it
				Constant* detailAsConstant = irgen->constantForDetail(*inst->detail);
				inliningParameters[1] = new GlobalVariable(*module, detailAsConstant->getType(), true, GlobalValue::PrivateLinkage, detailAsConstant);
				irgen->inlineFunction(fn, implementation, inliningParameters, *functionMap, blockMap, nextInstAddress);
			}
			else
			{
				createAsmCall(*targetInfo, *inst, registers, *thisBlock);
				BasicBlock* target = blockMap.blockToInstruction(nextInstAddress);
				BranchInst::Create(target, thisBlock);
			}
			continue;
		}
		break;
	}
	
#if DEBUG && 0
	// check that it still works
	if (verifyModule(*module, &errs()))
	{
		module->dump();
		abort();
	}
#endif
	
	return fn;
}

std::unordered_set<uint64_t> TranslationContext::getDiscoveredEntryPoints() const
{
	std::unordered_set<uint64_t> entryPoints;
	functionMap->getDiscoveredEntryPoints(entryPoints);
	return entryPoints;
}

unique_ptr<Module> TranslationContext::take()
{
	return move(module);
}
