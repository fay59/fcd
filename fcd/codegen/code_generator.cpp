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

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Support/SourceMgr.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

extern "C" const char fcd_emulator_start_x86;
extern "C" const char fcd_emulator_end_x86;

namespace
{
	class TranslationCloningDirector;
	
	class x86CodeGenerator : public CodeGenerator
	{
		Value* ipOffset[3];
		
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
			
			return true;
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
