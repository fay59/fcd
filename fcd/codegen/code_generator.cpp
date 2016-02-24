//
// code_generator.cpp
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

#include "code_generator.h"
#include "metadata.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Support/SourceMgr.h>
SILENCE_LLVM_WARNINGS_END()

#include <string>

using namespace llvm;
using namespace std;

extern "C" const char fcd_emulator_start_x86;
extern "C" const char fcd_emulator_end_x86;

namespace
{
	Type* getMemoryType(LLVMContext& ctx, size_t size)
	{
		if (size == 1 || size == 2 || size == 4 || size == 8)
		{
			return Type::getIntNTy(ctx, static_cast<unsigned>(size * 8));
		}
		llvm_unreachable("invalid pointer size");
	}
	
	class x86CodeGenerator : public CodeGenerator
	{
		Value* ipOffset[3];
		vector<Function*> declarations;
		
		bool isIntrinsic(StringRef name)
		{
			static unordered_set<string> x86Intrins = {
				"x86_jump_intrin", "x86_call_intrin", "x86_ret_intrin", "x86_read_mem", "x86_write_mem"
			};
			
			return x86Intrins.count(name) != 0;
		}
		
		void replaceIntrinsic(AddressToFunction& funcMap, AddressToBlock& blockMap, StringRef name, CallInst* translated)
		{
			if (name == "x86_jump_intrin")
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
			}
			else if (name == "x86_call_intrin")
			{
				if (auto constantDestination = dyn_cast<ConstantInt>(translated->getOperand(2)))
				{
					uint64_t destination = constantDestination->getLimitedValue();
					Function* target = funcMap.getCallTarget(destination);
					CallInst* replacement = CallInst::Create(target, {translated->getOperand(1)}, "", translated);
					translated->replaceAllUsesWith(replacement);
					translated->eraseFromParent();
				}
			}
			else if (name == "x86_ret_intrin")
			{
				BasicBlock* parent = translated->getParent();
				BasicBlock* remainder = parent->splitBasicBlock(translated);
				parent->getTerminator()->eraseFromParent();
				remainder->eraseFromParent();
				ReturnInst::Create(translated->getContext(), parent);
			}
			else if (name == "x86_read_mem")
			{
				Value* intptr = translated->getOperand(0);
				ConstantInt* sizeOperand = cast<ConstantInt>(translated->getOperand(1));
				Type* loadType = getMemoryType(translated->getContext(), sizeOperand->getLimitedValue());
				CastInst* pointer = CastInst::Create(CastInst::IntToPtr, intptr, loadType->getPointerTo(), "", translated);
				Instruction* replacement = new LoadInst(pointer, "", translated);
				md::setProgramMemory(*replacement);
				
				Type* i64 = Type::getInt64Ty(translated->getContext());
				if (replacement->getType() != i64)
				{
					replacement = CastInst::Create(Instruction::ZExt, replacement, i64, "", translated);
				}
				translated->replaceAllUsesWith(replacement);
				translated->eraseFromParent();
			}
			else if (name == "x86_write_mem")
			{
				Value* intptr = translated->getOperand(0);
				Value* value = translated->getOperand(2);
				ConstantInt* sizeOperand = cast<ConstantInt>(translated->getOperand(1));
				Type* storeType = getMemoryType(translated->getContext(), sizeOperand->getLimitedValue());
				CastInst* pointer = CastInst::Create(CastInst::IntToPtr, intptr, storeType->getPointerTo(), "", translated);
				
				if (value->getType() != storeType)
				{
					// Assumption: storeType can only be smaller than the type of storeValue
					value = CastInst::Create(Instruction::Trunc, value, storeType, "", translated);
				}
				StoreInst* storeInst = new StoreInst(value, pointer, translated);
				md::setProgramMemory(*storeInst);
				translated->eraseFromParent();
			}
		}
		
	protected:
		virtual bool init() override
		{
			if (!initGenerator(&fcd_emulator_start_x86, &fcd_emulator_end_x86))
			{
				return false;
			}
			
			Type* i32 = Type::getInt32Ty(context());
			Type* i64 = Type::getInt64Ty(context());
			ipOffset[0] = ConstantInt::get(i64, 0);
			ipOffset[1] = ConstantInt::get(i32, 9);
			ipOffset[2] = ConstantInt::get(i32, 0);
			auto& funcs = getFunctionMap();
			funcs.resize(X86_INS_ENDING);
			
#define X86_INSTRUCTION_DECL(e, n) funcs[e] = getFunction("x86_" #n);
#include "x86_insts.h"
			
			for (Function& fn : module().getFunctionList())
			{
				if (fn.isDeclaration())
				{
					declarations.push_back(&fn);
				}
			}
			
			return true;
		}
		
		virtual void getModuleLevelValueChanges(llvm::ValueToValueMapTy& map, llvm::Module& targetModule) override
		{
			for (Function* decl : declarations)
			{
				map[decl] = targetModule.getOrInsertFunction(decl->getName(), decl->getFunctionType(), decl->getAttributes());
			}
		}
		
		virtual void resolveIntrinsics(llvm::Function& targetFunction, AddressToFunction& funcMap, AddressToBlock& blockMap) override
		{
			Module& module = *targetFunction.getParent();
			for (Function* decl : declarations)
			{
				StringRef name = decl->getName();
				Function* matching = module.getFunction(name);
				if (isIntrinsic(name))
				{
					auto iter = matching->use_begin();
					while (iter != matching->use_end())
					{
						auto call = cast<CallInst>(iter->getUser());
						++iter;
						replaceIntrinsic(funcMap, blockMap, name, call);
					}
				}
			}
		}
		
	public:
		x86CodeGenerator(LLVMContext& ctx)
		: CodeGenerator(ctx)
		{
		}
		
		virtual Constant* constantForDetail(const cs_detail& detail) override
		{
			LLVMContext& ctx = context();
			Module& module = this->module();
			
			Type* int8Ty = Type::getInt8Ty(ctx);
			Type* int32Ty = Type::getInt32Ty(ctx);
			Type* int64Ty = Type::getInt64Ty(ctx);
			
			const cs_x86& cs = detail.x86;
			StructType* x86Ty = module.getTypeByName("struct.cs_x86");
			StructType* x86Op = module.getTypeByName("struct.cs_x86_op");
			StructType* x86OpMem = module.getTypeByName("struct.x86_op_mem");
			StructType* x86OpMemWrapper = module.getTypeByName("union.anon");
			
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
		
		virtual Function* implementationForPrologue() override
		{
			return getFunction("x86_function_prologue");
		}
		
		virtual llvm::StructType* getRegisterTy() override
		{
			return module().getTypeByName("struct.x86_regs");
		}
		
		virtual llvm::StructType* getFlagsTy() override
		{
			return module().getTypeByName("struct.x86_flags_reg");
		}
		
		virtual llvm::StructType* getConfigTy() override
		{
			return module().getTypeByName("struct.x86_config");
		}
		
		virtual ArrayRef<Value*> getIpOffset() override
		{
			return ArrayRef<Value*>(begin(ipOffset), end(ipOffset));
		}
	};
}

CodeGenerator::CodeGenerator(llvm::LLVMContext& ctx)
: ctx(ctx)
{
}

bool CodeGenerator::initGenerator(const char* begin, const char* end)
{
	SMDiagnostic errors;
	MemoryBufferRef buffer(StringRef(begin, end - begin), "IRImplementation");
	if (auto module = parseIR(buffer, errors, ctx))
	{
		generatorModule = move(module);
		return true;
	}
	else
	{
		errors.print(nullptr, errs());
		assert(false);
		return false;
	}
}

unique_ptr<CodeGenerator> CodeGenerator::x86(LLVMContext &ctx)
{
	unique_ptr<CodeGenerator> codegen(new x86CodeGenerator(ctx));
	if (codegen->init())
	{
		return codegen;
	}
	return nullptr;
}

void CodeGenerator::inlineFunction(Function *target, Function *toInline, ArrayRef<Value *> parameters, AddressToFunction& funcMap, AddressToBlock &blockMap, uint64_t nextAddress)
{
	assert(toInline->arg_size() == parameters.size());
	Module& targetModule = *target->getParent();
	auto iter = toInline->arg_begin();
	
	ValueToValueMapTy valueMap;
	getModuleLevelValueChanges(valueMap, targetModule);
	for (Value* parameter : parameters)
	{
		valueMap[static_cast<Argument*>(iter)] = parameter;
		++iter;
	}
	
	SmallVector<ReturnInst*, 1> returns;
	Function::iterator blockBeforeInstruction = target->back().getIterator();
	CloneAndPruneFunctionInto(target, toInline, valueMap, true, returns);
	
	// Stitch blocks together
	Function::iterator firstNewBlock = blockBeforeInstruction;
	++firstNewBlock;
	BranchInst::Create(static_cast<BasicBlock*>(firstNewBlock), static_cast<BasicBlock*>(blockBeforeInstruction));
	
	// Redirect returns
	BasicBlock* nextBlock = blockMap.blockToInstruction(nextAddress);
	for (auto ret : returns)
	{
		BranchInst::Create(nextBlock, ret);
		ret->eraseFromParent();
	}
	
	resolveIntrinsics(*target, funcMap, blockMap);
}
