//
//  translation_context.cpp
//  x86Emulator
//
//  Created by Félix on 2015-04-20.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Transforms/Scalar.h>
#include <iostream>
#include <unordered_set>
#include <vector>

#include "translation_context.h"

using namespace llvm;
using namespace std;

namespace
{
	typedef void (x86::*irgen_method)(llvm::Value*, llvm::Value*, llvm::Value*);
	
	irgen_method method_table[] = {
		#define X86_INSTRUCTION_DECL(e, n) [e] = &x86::x86_##n,
		#include "x86_defs.h"
	};
	
	template<typename T, size_t N>
	vector<typename remove_const<T>::type> array_to_vector(T (&array)[N])
	{
		return vector<typename remove_const<T>::type>(begin(array), end(array));
	}
	
	void resolve_intrinsics(result_function& fn, unordered_set<uint64_t>& new_labels)
	{
		auto iter = fn.intrin_begin();
		while (iter != fn.intrin_end())
		{
			auto call = cast<CallInst>((*iter)->begin());
			auto name = call->getCalledValue()->getName();
			if (name == "x86_jump_intrin")
			{
				if (auto constantDestination = dyn_cast<ConstantInt>(call->getOperand(2)))
				{
					uint64_t dest = constantDestination->getLimitedValue();
					BasicBlock* replacement = BasicBlock::Create(fn->getContext());
					BranchInst::Create(&fn.get_destination(dest), replacement);
					iter = fn.replace(iter, replacement);
					
					if (fn.get_implemented_block(dest) == nullptr)
					{
						new_labels.insert(dest);
					}
					continue;
				}
			}
			else if (name == "x86_ret_intrin")
			{
				BasicBlock* replacement = BasicBlock::Create(fn->getContext());
				ReturnInst::Create(fn->getContext(), replacement);
				iter = fn.replace(iter, replacement);
				continue;
			}
			iter++;
		}
	}
}

translation_context::translation_context(LLVMContext& context, const x86_config& config, const std::string& module_name)
: context(context)
, module(new Module(module_name, context))
, cs(CS_ARCH_X86, CS_MODE_LITTLE_ENDIAN)
, irgen(context, *module)
, identifyJumpTargets(module.get())
{
	voidTy = Type::getVoidTy(context);
	int32Ty = IntegerType::getInt32Ty(context);
	int64Ty = IntegerType::getInt64Ty(context);
	x86RegsTy = cast<StructType>(irgen.type_by_name("struct.x86_regs"));
	x86ConfigTy = cast<StructType>(irgen.type_by_name("struct.x86_config"));
	resultFnTy = FunctionType::get(voidTy, ArrayRef<Type*>(PointerType::get(x86RegsTy, 0)), false);
	
	Constant* x86ConfigConst = ConstantStruct::get(x86ConfigTy,
		ConstantInt::get(int64Ty, config.address_size),
		ConstantInt::get(int32Ty, config.ip),
		ConstantInt::get(int32Ty, config.sp),
		ConstantInt::get(int32Ty, config.fp),
		nullptr);
	x86Config = new GlobalVariable(*module, x86ConfigTy, true, GlobalVariable::PrivateLinkage, x86ConfigConst, "x86_config");
	
	identifyJumpTargets.add(createInstructionCombiningPass());
	identifyJumpTargets.add(createCFGSimplificationPass());
	identifyJumpTargets.doInitialization();
}

translation_context::~translation_context()
{
	identifyJumpTargets.doFinalization();
}

Constant* translation_context::cs_struct(const cs_x86 &cs)
{
	Type* int8 = IntegerType::getInt8Ty(context);
	Type* int32 = IntegerType::getInt32Ty(context);
	Type* int64 = IntegerType::getInt64Ty(context);
	StructType* x86Ty = cast<StructType>(irgen.type_by_name("struct.cs_x86"));
	StructType* x86Op = cast<StructType>(irgen.type_by_name("struct.cs_x86_op"));
	StructType* x86OpMem = cast<StructType>(irgen.type_by_name("struct.x86_op_mem"));
	StructType* x86OpMemWrapper = cast<StructType>(irgen.type_by_name("union.anon"));
	
	vector<Constant*> operands;
	for (size_t i = 0; i < 8; i++)
	{
		vector<Constant*> structFields {
			ConstantInt::get(int32, cs.operands[i].mem.segment),
			ConstantInt::get(int32, cs.operands[i].mem.base),
			ConstantInt::get(int32, cs.operands[i].mem.index),
			ConstantInt::get(int32, cs.operands[i].mem.scale),
			ConstantInt::get(int64, cs.operands[i].mem.disp),
		};
		Constant* opMem = ConstantStruct::get(x86OpMem, structFields);
		Constant* wrapper = ConstantStruct::get(x86OpMemWrapper, opMem, nullptr);
		
		structFields = {
			ConstantInt::get(int32, cs.operands[i].type),
			wrapper,
			ConstantInt::get(int8, cs.operands[i].size),
			ConstantInt::get(int32, cs.operands[i].avx_bcast),
			ConstantInt::get(int8, cs.operands[i].avx_zero_opmask),
		};
		operands.push_back(ConstantStruct::get(x86Op, structFields));
	}
	
	vector<Constant*> fields = {
		ConstantDataArray::get(context, array_to_vector(cs.prefix)),
		ConstantDataArray::get(context, array_to_vector(cs.opcode)),
		ConstantInt::get(int8, cs.rex),
		ConstantInt::get(int8, cs.addr_size),
		ConstantInt::get(int8, cs.modrm),
		ConstantInt::get(int8, cs.sib),
		ConstantInt::get(int32, cs.disp),
		ConstantInt::get(int32, cs.sib_index),
		ConstantInt::get(int8, cs.sib_scale),
		ConstantInt::get(int32, cs.sib_base),
		ConstantInt::get(int32, cs.sse_cc),
		ConstantInt::get(int32, cs.avx_cc),
		ConstantInt::get(int8, cs.avx_sae),
		ConstantInt::get(int32, cs.avx_rm),
		ConstantInt::get(int8, cs.op_count),
		ConstantArray::get(ArrayType::get(x86Op, 8), operands),
	};
	return ConstantStruct::get(x86Ty, fields);
}

Function* translation_context::single_step(const cs_insn &inst)
{
	string functionName = "asm_";
	raw_string_ostream functionNameStream(functionName);
	functionNameStream.write_hex(inst.address);
	functionNameStream.flush();
	
	// create a const global for the instruction itself
	auto instAsValue = cs_struct(inst.detail->x86);
	auto instAddress = new GlobalVariable(*module, instAsValue->getType(), true, GlobalValue::PrivateLinkage, instAsValue);
	
	irgen.start_function(*resultFnTy, functionName);
	irgen.function->addAttribute(1, Attribute::NoAlias);
	irgen.function->addAttribute(1, Attribute::NoCapture);
	irgen.function->addAttribute(1, Attribute::NonNull);
	Value* x86RegsAddress = irgen.function->arg_begin();
	Value* ipAddress = irgen.builder.CreateInBoundsGEP(x86RegsAddress, {
		ConstantInt::get(int64Ty, 0),
		ConstantInt::get(int32Ty, 9),
		ConstantInt::get(int32Ty, 0),
	});
	
	irgen.builder.CreateStore(ConstantInt::get(int64Ty, inst.address), ipAddress);
	(irgen.*method_table[inst.id])(x86Config, x86RegsAddress, instAddress);
	
	BasicBlock* terminatingBlock = irgen.builder.GetInsertBlock();
	if (terminatingBlock->getTerminator() == nullptr)
	{
		Constant* nextAddress = ConstantInt::get(int64Ty, inst.address + inst.size);
		irgen.builder.CreateCall3(module->getFunction("x86_jump_intrin"), x86Config, x86RegsAddress, nextAddress);
		irgen.builder.CreateUnreachable();
	}
	
	return irgen.end_function();
}

result_function translation_context::create_function(const std::string &name, uint64_t base_address, const uint8_t* begin, const uint8_t* end)
{
	result_function result(*module, *resultFnTy, name);
	
	unordered_set<uint64_t> blocksToVisit { base_address };
	while (blocksToVisit.size() > 0)
	{
		auto visitIter = blocksToVisit.begin();
		uint64_t branch = *visitIter;
		blocksToVisit.erase(visitIter);
		
		const uint8_t* code = begin + (branch - base_address);
		auto iter = cs.begin(code, end, branch);
		auto next_result = iter.next();
		while (next_result == capstone_iter::success)
		{
			Function* func = single_step(*iter);
			identifyJumpTargets.run(*func);
			result.eat(func, iter->address);
			
#if DEBUG
			// check that it still works
			raw_os_ostream rerr(cerr);
			if (verifyModule(*module, &rerr))
			{
				rerr.flush();
				module->dump();
				abort();
			}
#endif
			
			if (iter->id == X86_INS_JMP || iter->id == X86_INS_RET)
			{
				break;
			}
			next_result = iter.next();
		}
		
		if (next_result == capstone_iter::invalid_data)
		{
			irgen.start_function(*resultFnTy, "unreachable");
			irgen.builder.CreateUnreachable();
			result.eat(irgen.end_function(), iter.next_address());
		}
		
		resolve_intrinsics(result, blocksToVisit);
	}
	
	return result;
}

unique_ptr<Module> translation_context::take()
{
	return move(module);
}
