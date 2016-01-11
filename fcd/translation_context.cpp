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
#include "translation_context.h"
#include "x86_register_map.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/Triple.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Cloning.h>
SILENCE_LLVM_WARNINGS_END()

#include <array>
#include <unordered_set>
#include <vector>

using namespace llvm;
using namespace std;

extern "C" const char fcd_emulator_start_x86;
extern "C" const char fcd_emulator_end_x86;

namespace
{
	class TranslationCloningDirector;
}

class CodeGenerator
{
	typedef Constant* (CodeGenerator::*ConstantFromCapstone)(const cs_detail&);
	
	LLVMContext& ctx;
	unique_ptr<Module> module;
	vector<Function*> functionByOpcode;
	Function* prologue;
	
	NOT_NULL(Type) registerType;
	NOT_NULL(Type) flagsType;
	NOT_NULL(Type) configType;
	SmallVector<Value*, 3> ipOffset;
	
	ConstantFromCapstone constantBuilder;
	
	CodeGenerator(LLVMContext& ctx)
	: ctx(ctx), registerType(Type::getVoidTy(ctx)), flagsType(Type::getVoidTy(ctx)), configType(Type::getVoidTy(ctx))
	{
	}
	
	bool init(const char* begin, const char* end)
	{
		SMDiagnostic errors;
		MemoryBufferRef buffer(StringRef(begin, end - begin), "IRImplementation");
		if (auto module = parseIR(buffer, errors, ctx))
		{
			this->module = move(module);
			return true;
		}
		else
		{
			errors.print(nullptr, errs());
			assert(false);
			return false;
		}
	}
	
	Function* getFunction(const char* name)
	{
		auto result = module->getFunction(name);
		assert(result != nullptr);
		return result;
	}
	
	Constant* constantForX86(const cs_detail& detail)
	{
		Type* int8Ty = Type::getInt8Ty(ctx);
		Type* int32Ty = Type::getInt32Ty(ctx);
		Type* int64Ty = Type::getInt64Ty(ctx);
		
		const cs_x86& cs = detail.x86;
		StructType* x86Ty = module->getTypeByName("struct.cs_x86");
		StructType* x86Op = module->getTypeByName("struct.cs_x86_op");
		StructType* x86OpMem = module->getTypeByName("struct.x86_op_mem");
		StructType* x86OpMemWrapper = module->getTypeByName("union.anon");
		
		vector<Constant*> operands;
		for (size_t i = 0; i < 8; i++)
		{
			vector<Constant*> structFields {
				ConstantInt::get(int32Ty, cs.operands[i].mem.segment),
				ConstantInt::get(int32Ty, cs.operands[i].mem.base),
				ConstantInt::get(int32Ty, cs.operands[i].mem.index),
				ConstantInt::get(int32Ty, cs.operands[i].mem.scale),
				ConstantInt::get(int64Ty, cs.operands[i].mem.disp),
			};
			Constant* opMem = ConstantStruct::get(x86OpMem, structFields);
			Constant* wrapper = ConstantStruct::get(x86OpMemWrapper, opMem, nullptr);
			
			structFields = {
				ConstantInt::get(int32Ty, cs.operands[i].type),
				wrapper,
				ConstantInt::get(int8Ty, cs.operands[i].size),
				ConstantInt::get(int32Ty, cs.operands[i].avx_bcast),
				ConstantInt::get(int8Ty, cs.operands[i].avx_zero_opmask),
			};
			operands.push_back(ConstantStruct::get(x86Op, structFields));
		}
		
		vector<Constant*> fields = {
			ConstantDataArray::get(ctx, ArrayRef<uint8_t>(begin(cs.prefix), end(cs.prefix))),
			ConstantDataArray::get(ctx, ArrayRef<uint8_t>(begin(cs.opcode), end(cs.opcode))),
			ConstantInt::get(int8Ty, cs.rex),
			ConstantInt::get(int8Ty, cs.addr_size),
			ConstantInt::get(int8Ty, cs.modrm),
			ConstantInt::get(int8Ty, cs.sib),
			ConstantInt::get(int32Ty, cs.disp),
			ConstantInt::get(int32Ty, cs.sib_index),
			ConstantInt::get(int8Ty, cs.sib_scale),
			ConstantInt::get(int32Ty, cs.sib_base),
			ConstantInt::get(int32Ty, cs.sse_cc),
			ConstantInt::get(int32Ty, cs.avx_cc),
			ConstantInt::get(int8Ty, cs.avx_sae),
			ConstantInt::get(int32Ty, cs.avx_rm),
			ConstantInt::get(int8Ty, cs.op_count),
			ConstantArray::get(ArrayType::get(x86Op, 8), operands),
		};
		return ConstantStruct::get(x86Ty, fields);
	}
	
public:
	static unique_ptr<CodeGenerator> x86(LLVMContext& ctx)
	{
		unique_ptr<CodeGenerator> codegen(new CodeGenerator(ctx));
		if (!codegen->init(&fcd_emulator_start_x86, &fcd_emulator_end_x86))
		{
			return nullptr;
		}
		
		codegen->registerType = codegen->module->getTypeByName("struct.x86_regs");
		codegen->flagsType = codegen->module->getTypeByName("struct.x86_flags_reg");
		codegen->configType = codegen->module->getTypeByName("struct.x86_config");
		codegen->constantBuilder = &CodeGenerator::constantForX86;
		
		Type* i32 = Type::getInt32Ty(ctx);
		Type* i64 = Type::getInt64Ty(ctx);
		codegen->ipOffset = { ConstantInt::get(i64, 0), ConstantInt::get(i32, 9), ConstantInt::get(i32, 0) };
		
		codegen->prologue = codegen->getFunction("x86_function_prologue");
		auto& funcs = codegen->functionByOpcode;
		funcs.resize(X86_INS_ENDING);
		
#define X86_INSTRUCTION_DECL(e, n) funcs[e] = codegen->getFunction("x86_" #n);
#include "x86_defs.h"
		
		return codegen;
	}
	
	Function* implementationFor(unsigned index)
	{
		return functionByOpcode.at(index);
	}
	
	Function* implementationForPrologue()
	{
		return prologue;
	}
	
	StructType* getRegisterTy() { return cast<StructType>(registerType); }
	StructType* getFlagsTy() { return cast<StructType>(flagsType); }
	StructType* getConfigTy() { return cast<StructType>(configType); }
	const SmallVectorImpl<Value*>& getIpOffset() const { return ipOffset; }
	
	Constant* constantForDetail(const cs_detail& detail)
	{
		return (this->*constantBuilder)(detail);
	}
	
	void inlineFunction(Function* target, Function* toInline, ArrayRef<Value*> parameters, TranslationCloningDirector& director, uint64_t nextAddress);
};

class AddressToFunction
{
	Module& module;
	FunctionType& fnType;
	unordered_map<uint64_t, string> aliases;
	unordered_map<uint64_t, Function*> functions;
	
	Function* createFunction(const Twine& name)
	{
		// XXX: do we really want external linkage? this has an impact on possible optimizations
		return Function::Create(&fnType, GlobalValue::ExternalLinkage, name, &module);
	}
	
public:
	AddressToFunction(Module& module, FunctionType& fnType)
	: module(module), fnType(fnType)
	{
	}
	
	void setAlias(string alias, uint64_t address)
	{
		auto result = aliases.insert({address, move(alias)});
		assert(result.second);
	}
	
	string nameForAddress(uint64_t address)
	{
		auto iter = aliases.find(address);
		if (iter != aliases.end())
		{
			return iter->second;
		}
		
		string result;
		(raw_string_ostream(result) << "func_").write_hex(address);
		return result;
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
			result = createFunction(nameForAddress(address));
			// Give it a body but mark it as a "prototype".
			// This is necessary because you can't attach metadata to a function without a body;
			// however, we rely on metadata to figure out whether a function must have its arguments recovered.
			LLVMContext& ctx = module.getContext();
			Type* voidTy = Type::getVoidTy(ctx);
			Type* i8Ptr = Type::getInt8PtrTy(ctx);
			FunctionType* protoIntrinType = FunctionType::get(voidTy, { i8Ptr }, false);
			Function* protoIntrin = cast<Function>(module.getOrInsertFunction("/fcd/prototype", protoIntrinType));
			BasicBlock* body = BasicBlock::Create(ctx, "", result);
			auto bitcast = CastInst::Create(CastInst::BitCast, result->arg_begin(), i8Ptr, "", body);
			CallInst::Create(protoIntrin, {bitcast}, "", body);
			ReturnInst::Create(ctx, body);
			
			md::setPrototype(*result);
			md::setVirtualAddress(*result, address);
		}
		return result;
	}
	
	Function* createFunction(uint64_t address)
	{
		Function*& result = functions[address];
		if (result == nullptr)
		{
			result = createFunction(nameForAddress(address));
		}
		else if (!md::isPrototype(*result))
		{
			// the function needs to be fresh and new
			return nullptr;
		}
		
		// reset prototype status (and everything else, really)
		result->deleteBody();
		BasicBlock::Create(result->getContext(), "entry", result);
		md::setVirtualAddress(*result, address);
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
			default: throw invalid_argument("address_size");
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
			
			// set block name (aesthetic reasons)
			char blockName[] = "0000000000000000";
			snprintf(blockName, sizeof blockName, "%016llx", address);
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
			throw invalid_argument("size");
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
			}
			
			for (const CallInst* call : delayedCalls)
			{
				if (auto translated = dyn_cast_or_null<CallInst>(vmap[call]))
				if (auto constantDestination = dyn_cast<ConstantInt>(translated->getOperand(2)))
				{
					uint64_t destination = constantDestination->getLimitedValue();
					Function* target = functionMap.getCallTarget(destination);
					CallInst* replacement = CallInst::Create(target, {translated->getOperand(1)}, "", translated);
					translated->replaceAllUsesWith(replacement);
					translated->eraseFromParent();
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
}

void CodeGenerator::inlineFunction(Function *target, Function *toInline, ArrayRef<llvm::Value *> parameters, TranslationCloningDirector &director, uint64_t nextAddress)
{
	auto iter = toInline->arg_begin();
	
	ValueToValueMapTy valueMap;
	for (Value* parameter : parameters)
	{
		valueMap[iter] = parameter;
		++iter;
	}
	
	SmallVector<ReturnInst*, 1> returns;
	Function::iterator lastBlock = &target->back();
	CloneAndPruneIntoFromInst(target, toInline, toInline->front().begin(), valueMap, true, returns, "", nullptr, &director);
	
	// Stitch blocks together
	Function::iterator firstNewBlock = lastBlock;
	++firstNewBlock;
	BranchInst::Create(firstNewBlock, lastBlock);
	
	director.performDelayedOperations(valueMap, returns, nextAddress);
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

string TranslationContext::nameOf(uint64_t address) const
{
	return functionMap->nameForAddress(address);
}

void TranslationContext::createAlias(uint64_t address, const std::string& name)
{
	functionMap->setAlias(name, address);
}

Function* TranslationContext::createFunction(uint64_t baseAddress, const uint8_t* begin, const uint8_t* end)
{
	Function* fn = functionMap->createFunction(baseAddress);
	assert(fn != nullptr);
	
	AddressToBlock blockMap(*fn);
	BasicBlock* entry = &fn->back();
	TranslationCloningDirector director(*module, *functionMap, blockMap);
	
	Argument* registers = fn->arg_begin();
	auto flags = new AllocaInst(irgen->getFlagsTy(), "flags", entry);
	
	ArrayRef<Value*> ipGepIndices = irgen->getIpOffset();
	auto ipPointer = GetElementPtrInst::CreateInBounds(registers, ipGepIndices, "", entry);
	Type* ipType = GetElementPtrInst::getIndexedType(irgen->getRegisterTy(), ipGepIndices);
	
	Function* prologue = irgen->implementationForPrologue();
	irgen->inlineFunction(fn, prologue, { configVariable, registers }, director, baseAddress);
	
	uint64_t nextAddress;
	auto inst = cs->alloc();
	SmallVector<Value*, 4> inliningParameters = { configVariable, nullptr, registers, flags };
	while (blockMap.getOneStub(nextAddress))
	{
		auto address = begin + (nextAddress - baseAddress);
		if (address >= end || address < begin)
		{
			assert(false);
			break;
		}
		
		if (auto result = cs->disassemble(move(inst), address, end, nextAddress))
		{
			inst = move(result);
			BasicBlock* thisBlock = blockMap.implementInstruction(inst->address);
			if (thisBlock == nullptr)
			{
				// already implemented
				break;
			}
			
			// store instruction pointer
			auto ipValue = ConstantInt::get(ipType, inst->address);
			new StoreInst(ipValue, ipPointer, false, thisBlock);
			
			Function* implementation = irgen->implementationFor(inst->id);
			Constant* detailAsConstant = irgen->constantForDetail(*inst->detail);
			inliningParameters[1] = new GlobalVariable(*module, detailAsConstant->getType(), true, GlobalValue::PrivateLinkage, detailAsConstant);
			irgen->inlineFunction(fn, implementation, inliningParameters, director, inst->address + inst->size);
		}
		else
		{
			break;
		}
	}
	
#if DEBUG
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
