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

#include "llvm_warnings.h"
#include "metadata.h"
#include "not_null.h"
#include "params_registry.h"
#include "translation_context.h"
#include "x86_register_map.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/Triple.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Cloning.h>
SILENCE_LLVM_WARNINGS_END()

#include <array>
#include <unordered_set>
#include <vector>

using namespace llvm;
using namespace std;

class AddressToFunction
{
	Module& module;
	FunctionType& fnType;
	unordered_map<uint64_t, string> aliases;
	unordered_map<uint64_t, Function*> functions;
	
	Function* insertFunction(uint64_t address)
	{
		char defaultName[] = "func_0000000000000000";
		snprintf(defaultName, sizeof defaultName, "func_%" PRIx64, address);
		
		// XXX: do we really want external linkage? this has an impact on possible optimizations
		Function* fn = Function::Create(&fnType, GlobalValue::ExternalLinkage, defaultName, &module);
		md::setVirtualAddress(*fn, address);
		md::setIsPartOfOutput(*fn);
		md::setArgumentsRecoverable(*fn);
		return fn;
	}
	
public:
	AddressToFunction(Module& module, FunctionType& fnType)
	: module(module), fnType(fnType)
	{
	}
	
	size_t getDiscoveredEntryPoints(unordered_set<uint64_t>& entryPoints) const
	{
		size_t total = 0;
		for (const auto& pair : functions)
		{
			if (md::isPrototype(*pair.second))
			{
				entryPoints.insert(pair.first);
				++total;
			}
		}
		return total;
	}
	
	Function* getCallTarget(uint64_t address)
	{
		Function*& result = functions[address];
		
		if (result == nullptr)
		{
			result = insertFunction(address);
		}
		return result;
	}
	
	Function* createFunction(uint64_t address)
	{
		Function*& result = functions[address];
		if (result == nullptr)
		{
			result = insertFunction(address);
		}
		else if (!md::isPrototype(*result))
		{
			// the function needs to be fresh and new
			return nullptr;
		}
		
		// reset prototype status (and everything else, really)
		result->deleteBody();
		BasicBlock::Create(result->getContext(), "entry", result);
		md::setIsPartOfOutput(*result);
		md::setVirtualAddress(*result, address);
		md::setArgumentsRecoverable(*result);
		return result;
	}
};

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
	
	class AddressToBlock
	{
		Function& insertInto;
		BasicBlock* returnBlock;
		unordered_map<uint64_t, BasicBlock*> blocks;
		unordered_map<uint64_t, BasicBlock*> stubs;
		
	public:
		AddressToBlock(Function& fn)
		: insertInto(fn), returnBlock(nullptr)
		{
		}
		
		bool getOneStub(uint64_t& address) const
		{
			auto iter = stubs.begin();
			if (iter != stubs.end())
			{
				address = iter->first;
				return true;
			}
			return false;
		}
		
		BasicBlock* blockToInstruction(uint64_t address)
		{
			auto iter = blocks.find(address);
			if (iter != blocks.end())
			{
				return iter->second;
			}
			
			BasicBlock*& stub = stubs[address];
			if (stub == nullptr)
			{
				stub = BasicBlock::Create(insertInto.getContext(), "", &insertInto);
				ReturnInst::Create(insertInto.getContext(), stub);
			}
			return stub;
		}
		
		BasicBlock* implementInstruction(uint64_t address)
		{
			BasicBlock*& bodyBlock = blocks[address];
			if (bodyBlock != nullptr)
			{
				return nullptr;
			}
			
			bodyBlock = BasicBlock::Create(insertInto.getContext(), "", &insertInto);
			
			unsigned pointerSize = ((sizeof address * CHAR_BIT) - __builtin_clzll(address) + CHAR_BIT - 1) / CHAR_BIT * 2;
			
			// set block name (aesthetic reasons)
			char blockName[] = "0000000000000000";
			snprintf(blockName, sizeof blockName, "%0.*llx", pointerSize, address);
			bodyBlock->setName(blockName);
			
			auto iter = stubs.find(address);
			if (iter != stubs.end())
			{
				iter->second->replaceAllUsesWith(bodyBlock);
				iter->second->eraseFromParent();
				stubs.erase(iter);
			}
			return bodyBlock;
		}
	};
	
	class TranslationCloningDirector : public CloningDirector
	{
		Module& module;
		AddressToFunction& functionMap;
		AddressToBlock& blockMap;
		vector<const CallInst*> delayedJumps;
		vector<const CallInst*> delayedCalls;
		
		static Type* getMemoryType(LLVMContext& ctx, size_t size)
		{
			if (size == 1 || size == 2 || size == 4 || size == 8)
			{
				return Type::getIntNTy(ctx, static_cast<unsigned>(size * 8));
			}
			llvm_unreachable("invalid pointer size");
		}
		
		CloningAction fixFcdIntrinsic(ValueToValueMapTy& vmap, const CallInst& call, BasicBlock* bb)
		{
			Function* called = call.getCalledFunction();
			if (called == nullptr)
			{
				return CloneInstruction;
			}
			
			auto name = called->getName();
			if (name == "x86_jump_intrin")
			{
				// At this point there is probably not enough information to infer the
				// destination of the jump (or call) because CloneAndPruneInto only
				// simplifies PHINodes as it updates the CFG.
				delayedJumps.push_back(&call);
			}
			else if (name == "x86_call_intrin")
			{
				delayedCalls.push_back(&call);
			}
			else if (name == "x86_ret_intrin")
			{
				auto ret = ReturnInst::Create(call.getContext(), bb);
				md::setNonInlineReturn(*ret);
				return StopCloningBB;
			}
			else if (name == "x86_read_mem")
			{
				Value* intptr = vmap[call.getOperand(0)];
				ConstantInt* sizeOperand = cast<ConstantInt>(vmap[call.getOperand(1)]);
				Type* loadType = getMemoryType(call.getContext(), sizeOperand->getLimitedValue());
				CastInst* pointer = CastInst::Create(CastInst::IntToPtr, intptr, loadType->getPointerTo(), "", bb);
				Instruction* replacement = new LoadInst(pointer, "", bb);
				md::setProgramMemory(*replacement);
				
				Type* i64 = Type::getInt64Ty(call.getContext());
				if (replacement->getType() != i64)
				{
					replacement = CastInst::Create(Instruction::ZExt, replacement, i64, "", bb);
				}
				vmap[&call] = replacement;
				return SkipInstruction;
			}
			else if (name == "x86_write_mem")
			{
				Value* intptr = vmap[call.getOperand(0)];
				Value* value = vmap[call.getOperand(2)];
				ConstantInt* sizeOperand = cast<ConstantInt>(vmap[call.getOperand(1)]);
				Type* storeType = getMemoryType(call.getContext(), sizeOperand->getLimitedValue());
				CastInst* pointer = CastInst::Create(CastInst::IntToPtr, intptr, storeType->getPointerTo(), "", bb);
				
				if (value->getType() != storeType)
				{
					// Assumption: storeType can only be smaller than the type of storeValue
					value = CastInst::Create(Instruction::Trunc, value, storeType, "", bb);
				}
				StoreInst* storeInst = new StoreInst(value, pointer, bb);
				md::setProgramMemory(*storeInst);
				return SkipInstruction;
			}
			
			return CloneInstruction;
		}
		
	public:
		TranslationCloningDirector(Module& module, AddressToFunction& functionMap, AddressToBlock& blockMap)
		: module(module), functionMap(functionMap), blockMap(blockMap)
		{
		}
		
		void performDelayedOperations(ValueToValueMapTy& vmap, SmallVectorImpl<ReturnInst*>& returns, uint64_t nextAddress)
		{
			for (ReturnInst* ret : returns)
			{
				if (!md::isNonInlineReturn(*ret))
				{
					BranchInst::Create(blockMap.blockToInstruction(nextAddress), ret);
					ret->eraseFromParent();
				}
			}
			
			for (const CallInst* jump : delayedJumps)
			{
				if (auto translated = dyn_cast_or_null<CallInst>(vmap[jump]))
				{
					if (auto constantDestination = dyn_cast<ConstantInt>(translated->getOperand(2)))
					{
						BasicBlock* parent = translated->getParent();
						BasicBlock* remainder = parent->splitBasicBlock(translated);
						auto terminator = parent->getTerminator();
						
						uint64_t dest = constantDestination->getLimitedValue();
						BasicBlock* destination = blockMap.blockToInstruction(dest);
						BranchInst::Create(destination, terminator);
						terminator->eraseFromParent();
						remainder->eraseFromParent();
					}
					else
					{
						Function* intrin = jump->getCalledFunction();
						Value* inThisModule = module.getOrInsertFunction(intrin->getName(), intrin->getFunctionType(), intrin->getAttributes());
						translated->setCalledFunction(inThisModule);
					}
				}
			}
			
			for (const CallInst* call : delayedCalls)
			{
				if (auto translated = dyn_cast_or_null<CallInst>(vmap[call]))
				{
					if (auto constantDestination = dyn_cast<ConstantInt>(translated->getOperand(2)))
					{
						uint64_t destination = constantDestination->getLimitedValue();
						Function* target = functionMap.getCallTarget(destination);
						CallInst* replacement = CallInst::Create(target, {translated->getOperand(1)}, "", translated);
						translated->replaceAllUsesWith(replacement);
						translated->eraseFromParent();
					}
					else
					{
						Function* intrin = call->getCalledFunction();
						Value* inThisModule = module.getOrInsertFunction(intrin->getName(), intrin->getFunctionType(), intrin->getAttributes());
						translated->setCalledFunction(inThisModule);
					}
				}
			}
			
			delayedJumps.clear();
			delayedCalls.clear();
		}
		
		virtual CloningAction handleInstruction(ValueToValueMapTy& vmap, const Instruction* inst, BasicBlock* bb) override
		{
			if (auto call = dyn_cast<CallInst>(inst))
			{
				if (auto llvmIntrin = dyn_cast<IntrinsicInst>(call))
				{
					// the instruction cloner is a little dumb here so we need to tell it that
					// intrinsics are different in different modules
					Function* intrin = llvmIntrin->getCalledFunction();
					auto& handle = vmap[intrin];
					if (handle == nullptr)
					{
						handle = module.getOrInsertFunction(intrin->getName(), intrin->getFunctionType(), intrin->getAttributes());
					}
					return CloneInstruction;
				}
				else
				{
					return fixFcdIntrinsic(vmap, *call, bb);
				}
			}
			else
			{
				return CloneInstruction;
			}
		}
	};
	
	void inlineFunction(Function *target, Function *toInline, ArrayRef<llvm::Value *> parameters, TranslationCloningDirector &director, uint64_t nextAddress)
	{
		auto iter = toInline->arg_begin();
		
		ValueToValueMapTy valueMap;
		for (Value* parameter : parameters)
		{
			valueMap[iter] = parameter;
			++iter;
		}
		
		SmallVector<ReturnInst*, 1> returns;
		Function::iterator blockBeforeInstruction = &target->back();
		CloneAndPruneIntoFromInst(target, toInline, toInline->front().begin(), valueMap, true, returns, "", nullptr, &director);
		
		// Stitch blocks together
		Function::iterator firstNewBlock = blockBeforeInstruction;
		++firstNewBlock;
		BranchInst::Create(firstNewBlock, blockBeforeInstruction);
		
		director.performDelayedOperations(valueMap, returns, nextAddress);
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
			if (auto largest = target.largestOverlappingRegister(*registerInfo))
			{
				result.addParameter(ValueInformation::IntegerRegister, largest);
			}
		}
		
		// outputs
		for (size_t i = 0; i < detail.regs_write_count; ++i)
		{
			if (auto registerInfo = target.registerInfo(detail.regs_write[i]))
			if (auto largest = target.largestOverlappingRegister(*registerInfo))
			{
				result.addReturn(ValueInformation::IntegerRegister, largest);
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

TranslationContext::TranslationContext(LLVMContext& context, const x86_config& config, const std::string& module_name)
: context(context)
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
	
	if (auto csHandle = capstone::create(CS_ARCH_X86, CS_MODE_LITTLE_ENDIAN | cs_size_mode(config.address_size)))
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
	
	Triple triple;
	switch (config.isa)
	{
		case x86_isa32: triple.setArch(Triple::x86); break;
		case x86_isa64: triple.setArch(Triple::x86_64); break;
		default: llvm_unreachable("x86 ISA cannot map to target triple architecture");
	}
	triple.setOS(Triple::UnknownOS);
	triple.setVendor(Triple::UnknownVendor);
	
	module->setTargetTriple(triple.str());
}

TranslationContext::~TranslationContext()
{
}

void TranslationContext::setFunctionName(uint64_t address, const std::string &name)
{
	functionMap->getCallTarget(address)->setName(name);
}

Function* TranslationContext::createFunction(Executable& executable, uint64_t baseAddress)
{
	Function* fn = functionMap->createFunction(baseAddress);
	assert(fn != nullptr);
	
	auto targetInfo = TargetInfo::getTargetInfo(*module);
	AddressToBlock blockMap(*fn);
	BasicBlock* entry = &fn->back();
	TranslationCloningDirector director(*module, *functionMap, blockMap);
	
	Argument* registers = fn->arg_begin();
	auto flags = new AllocaInst(irgen->getFlagsTy(), "flags", entry);
	
	ArrayRef<Value*> ipGepIndices = irgen->getIpOffset();
	auto ipPointer = GetElementPtrInst::CreateInBounds(registers, ipGepIndices, "", entry);
	Type* ipType = GetElementPtrInst::getIndexedType(irgen->getRegisterTy(), ipGepIndices);
	
	Function* prologue = irgen->implementationForPrologue();
	inlineFunction(fn, prologue, { configVariable, registers }, director, baseAddress);
	
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
				inlineFunction(fn, implementation, inliningParameters, director, nextInstAddress);
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
