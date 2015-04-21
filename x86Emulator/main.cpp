//
//  main.cpp
//  x86Emulator
//
//  Created by Félix on 2015-04-17.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <fcntl.h>
#include <iostream>
#include <llvm/Analysis/Passes.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Scalar.h>
#include <memory>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <sys/mman.h>

#include "capstone_wrapper.h"
#include "x86.h"
#include "result_function.h"

using namespace llvm;
using namespace std;

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

Constant* cs_struct(LLVMContext& context, x86& irgen, const cs_x86* cs)
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
			ConstantInt::get(int32, cs->operands[i].mem.segment),
			ConstantInt::get(int32, cs->operands[i].mem.base),
			ConstantInt::get(int32, cs->operands[i].mem.index),
			ConstantInt::get(int32, cs->operands[i].mem.scale),
			ConstantInt::get(int64, cs->operands[i].mem.disp),
		};
		Constant* opMem = ConstantStruct::get(x86OpMem, structFields);
		Constant* wrapper = ConstantStruct::get(x86OpMemWrapper, opMem, nullptr);
		
		structFields = {
			ConstantInt::get(int32, cs->operands[i].type),
			wrapper,
			ConstantInt::get(int8, cs->operands[i].size),
			ConstantInt::get(int32, cs->operands[i].avx_bcast),
			ConstantInt::get(int8, cs->operands[i].avx_zero_opmask),
		};
		operands.push_back(ConstantStruct::get(x86Op, structFields));
	}
	
	vector<Constant*> fields = {
		ConstantDataArray::get(context, array_to_vector(cs->prefix)),
		ConstantDataArray::get(context, array_to_vector(cs->opcode)),
		ConstantInt::get(int8, cs->rex),
		ConstantInt::get(int8, cs->addr_size),
		ConstantInt::get(int8, cs->modrm),
		ConstantInt::get(int8, cs->sib),
		ConstantInt::get(int32, cs->disp),
		ConstantInt::get(int32, cs->sib_index),
		ConstantInt::get(int8, cs->sib_scale),
		ConstantInt::get(int32, cs->sib_base),
		ConstantInt::get(int32, cs->sse_cc),
		ConstantInt::get(int32, cs->avx_cc),
		ConstantInt::get(int8, cs->avx_sae),
		ConstantInt::get(int32, cs->avx_rm),
		ConstantInt::get(int8, cs->op_count),
		ConstantArray::get(ArrayType::get(x86Op, 8), operands),
	};
	return ConstantStruct::get(x86Ty, fields);
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
				new_labels.insert(dest);
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

Function* single_inst_function(Module& module, FunctionType& resultType, GlobalVariable& config, x86& irgen, const cs_insn& inst)
{
	LLVMContext& ctx = module.getContext();
	Type* int64 = Type::getInt64Ty(ctx);
	Type* int32 = Type::getInt32Ty(ctx);
	
	string functionName = "asm_";
	raw_string_ostream functionNameStream(functionName);
	functionNameStream.write_hex(inst.address);
	functionNameStream.flush();
	
	// create a const global for the instruction itself
	auto instAsValue = cs_struct(ctx, irgen, &inst.detail->x86);
	auto instAddress = new GlobalVariable(module, instAsValue->getType(), true, GlobalValue::PrivateLinkage, instAsValue);
	
	irgen.start_function(resultType, functionName);
	irgen.function->addAttribute(1, Attribute::NoAlias);
	irgen.function->addAttribute(1, Attribute::NoCapture);
	irgen.function->addAttribute(1, Attribute::NonNull);
	Value* x86RegsAddress = irgen.function->arg_begin();
	Value* ipAddress = irgen.builder.CreateInBoundsGEP(x86RegsAddress, {
		ConstantInt::get(int64, 0),
		ConstantInt::get(int32, 9),
		ConstantInt::get(int32, 0),
	});
	
	irgen.builder.CreateStore(ConstantInt::get(int64, inst.address), ipAddress);
	(irgen.*method_table[inst.id])(&config, x86RegsAddress, instAddress);
	
	BasicBlock* terminatingBlock = irgen.builder.GetInsertBlock();
	if (terminatingBlock->getTerminator() == nullptr)
	{
		irgen.builder.CreateCall3(module.getFunction("x86_jump_intrin"), &config, x86RegsAddress, ConstantInt::get(int64, inst.address + inst.size));
		irgen.builder.CreateUnreachable();
	}
	
	return irgen.end_function();
}

int compile(const uint8_t* begin, const uint8_t* end)
{
	capstone cs(CS_ARCH_X86, CS_MODE_LITTLE_ENDIAN);
	
	LLVMContext context;
	auto module = make_unique<Module>("fun-part", context);
	DataLayout layout("e-m:o-i64:64-f80:128-n8:16:32:64-S128");
	
	x86 irgen(context, *module);
	
	Type* voidTy = Type::getVoidTy(context);
	Type* int32 = IntegerType::getInt32Ty(context);
	Type* int64 = IntegerType::getInt64Ty(context);
	Type* x86RegsTy = irgen.type_by_name("struct.x86_regs");
	StructType* configTy = cast<StructType>(irgen.type_by_name("struct.x86_config"));
	FunctionType* resultFnTy = FunctionType::get(voidTy, ArrayRef<Type*>(PointerType::get(x86RegsTy, 0)), false);
	
	result_function result(*module, *resultFnTy, "x86_main");
	result->addAttribute(1, Attribute::NoAlias);
	result->addAttribute(1, Attribute::NoCapture);
	result->addAttribute(1, Attribute::NonNull);
	
	Constant* x86ConfigConst = ConstantStruct::get(configTy,
		ConstantInt::get(int64, 32),
		ConstantInt::get(int32, X86_REG_EIP),
		ConstantInt::get(int32, X86_REG_ESP),
		ConstantInt::get(int32, X86_REG_EBP),
		nullptr);
	GlobalVariable* configAddress = new GlobalVariable(*module, configTy, true, GlobalVariable::PrivateLinkage, x86ConfigConst, "x86_config");
	
	legacy::FunctionPassManager identifyJumpTargets(module.get());
	identifyJumpTargets.add(createInstructionCombiningPass());
	identifyJumpTargets.add(createCFGSimplificationPass());
	identifyJumpTargets.doInitialization();
	
	constexpr uint64_t baseAddress = 0x8048000;
	unordered_set<uint64_t> blocksToVisit { 0x80484a0 };
	while (blocksToVisit.size() > 0)
	{
		unordered_set<uint64_t> visitBeforeOptimizing;
		blocksToVisit.swap(visitBeforeOptimizing);
		while (visitBeforeOptimizing.size() > 0)
		{
			auto iter = visitBeforeOptimizing.begin();
			uint64_t nextAddress = *iter;
			visitBeforeOptimizing.erase(iter);
			
			const uint8_t* code = begin + (nextAddress - baseAddress);
			auto instIter = cs.begin(code, end, nextAddress);
			while (instIter.next() == capstone_iter::success)
			{
				if (result.get_implemented_block(instIter->address) != 0)
				{
					break;
				}
				
				Function* func = single_inst_function(*module, *resultFnTy, *configAddress, irgen, *instIter);
				identifyJumpTargets.run(*func);
				
				// append function to result
				result.eat(func, instIter->address);
				
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
				
				if (instIter->id == X86_INS_JMP || instIter->id == X86_INS_RET)
				{
					break;
				}
			}
		}
		
		// resolve jumps
		resolve_intrinsics(result, visitBeforeOptimizing);
		for (uint64_t value : visitBeforeOptimizing)
		{
			if (result.get_implemented_block(value) == nullptr)
			{
				blocksToVisit.insert(value);
			}
		}
	}
	
	identifyJumpTargets.doFinalization();
	
	// (actually) optimize result
	legacy::PassManager pm;
	PassManagerBuilder().populateModulePassManager(pm);
	pm.run(*module);
	
	raw_os_ostream rout(cout);
	module->print(rout, nullptr);
	result.take();
	
	return 0;
}

int main(int argc, const char** argv)
{
	if (argc != 2)
	{
		fprintf(stderr, "gimme a path you twat\n");
		return 1;
	}
	
	int file = open(argv[1], O_RDONLY);
	if (file == -1)
	{
		perror("open");
		return 1;
	}
	
	ssize_t size = lseek(file, 0, SEEK_END);
	
	void* data = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, file, 0);
	close(file);
	if (data == MAP_FAILED)
	{
		perror("mmap");
	}
	
	const uint8_t* begin = static_cast<const uint8_t*>(data);
	return compile(begin, begin + size);
}
