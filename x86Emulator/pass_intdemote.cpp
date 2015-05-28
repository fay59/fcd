//
//  pass_intdemote.cpp
//  x86Emulator
//
//  Created by Félix on 2015-04-24.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include "llvm_warnings.h"
#include "passes.h"

#include <deque>
#include <iostream>

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/LLVMContext.h>
SILENCE_LLVM_WARNINGS_END()

#include <string>
#include <unordered_map>
#include <unordered_set>

using namespace llvm;
using namespace std;

namespace
{
	struct IntegerDemotionAnalysis : public InstVisitor<IntegerDemotionAnalysis>
	{
		deque<Value*> stores;
		unordered_map<Value*, uint16_t> bitWidths;
		unordered_set<Value*> requiresTopBits;
		const DataLayout& dl;
		
		IntegerDemotionAnalysis(const DataLayout& dl)
		: dl(dl)
		{
		}
		
#pragma mark -
		void dump(Value* v, std::string prefix = "")
		{
			cout << prefix << '(' << get_width(*v);
			Type* t = v->getType();
			if (t->isSized())
			{
				size_t trueWidth = dl.getTypeSizeInBits(v->getType());
				cout << '/' << trueWidth;
			}
			cout << ") ";
			cout.flush();
			v->dump();
			
			if (auto user = dyn_cast<User>(v))
			{
				prefix += "-";
				for (auto iter = user->op_begin(); iter != user->op_end(); iter++)
				{
					dump(iter->get(), prefix);
				}
			}
		}
		
#pragma mark - Constant-sized values
		void visitConstant(Constant& c)
		{
			if (auto integer = dyn_cast<ConstantInt>(&c))
			{
				width(c) = integer->getValue().getActiveBits();
			}
			else
			{
				width(c) = dl.getTypeSizeInBits(c.getType());
			}
		}
		
		void visitGetElementPtrInst(GetElementPtrInst& i)
		{
			width(i, true) = dl.getTypeSizeInBits(i.getResultElementType());
		}
		
		void visitAllocaInst(AllocaInst& i)
		{
			width(i, true) = dl.getTypeSizeInBits(i.getType());
		}
		
		void visitLoadInst(LoadInst& i)
		{
			width(i, true) = dl.getTypeSizeInBits(i.getType());
		}
		
		void visitStoreInst(StoreInst& i)
		{
			stores.push_back(&i);
		}
		
		void visitCmpInst(CmpInst& i)
		{
			width(i, true) = 1;
		}
		
		void visitCastInst(CastInst& i)
		{
			uint16_t destinationWidth = dl.getTypeSizeInBits(i.getType());
			uint16_t operandWidth = get_width(i.getOperand(0));
			switch (i.getOpcode())
			{
				case CastInst::Trunc:
					width(i) = min(destinationWidth, operandWidth);
					break;
					
				case CastInst::ZExt:
				case CastInst::PtrToInt:
					width(i, true) = min(destinationWidth, operandWidth);
					break;
					
				case CastInst::SExt:
				case CastInst::FPToUI:
				case CastInst::UIToFP:
				case CastInst::SIToFP:
				case CastInst::FPTrunc:
				case CastInst::FPExt:
				case CastInst::IntToPtr:
				case CastInst::BitCast:
					width(i, true) = destinationWidth;
					break;
					
				default: llvm_unreachable("unhandled cast opcode");
			}
		}
		
		void visitSelectInst(SelectInst& i)
		{
			width(i) = max(get_width(i.getTrueValue()), get_width(i.getFalseValue()));
		}
		
		void visitBinaryOperator(BinaryOperator& i)
		{
			uint16_t typeWidth = dl.getTypeSizeInBits(i.getType());;
			uint16_t leftWidth = get_width(i.getOperand(0));
			uint16_t rightWidth = get_width(i.getOperand(1));
			uint64_t maxExpand;
			switch (i.getOpcode())
			{
				case BinaryOperator::Add:
					width(i) = min(typeWidth, uint16_t(max(leftWidth, rightWidth) + 1));
					break;
					
					// sign extension hurts
				case BinaryOperator::Sub:
					width(i) = typeWidth;
					break;
					
				case BinaryOperator::SDiv:
				case BinaryOperator::SRem:
				case BinaryOperator::AShr:
					width(i, true) = typeWidth;
					break;
					
				case BinaryOperator::Mul:
					width(i, true) = min(typeWidth, uint16_t(leftWidth + rightWidth));
					break;
					
				case BinaryOperator::LShr:
				case BinaryOperator::UDiv:
					width(i, true) = leftWidth;
					break;
					
				case BinaryOperator::URem:
					width(i, true) = rightWidth;
					break;
					
				case BinaryOperator::Shl:
					maxExpand = rightWidth < 6 ? (1ull << rightWidth) : typeWidth;
					width(i) = min(typeWidth, uint16_t(leftWidth + maxExpand));
					break;
					
				case BinaryOperator::And:
					width(i) = min(leftWidth, rightWidth);
					break;
					
				case BinaryOperator::Or:
				case BinaryOperator::Xor:
					width(i) = max(leftWidth, rightWidth);
					break;
					
				case BinaryOperator::FAdd:
				case BinaryOperator::FSub:
				case BinaryOperator::FMul:
				case BinaryOperator::FDiv:
				case BinaryOperator::FRem:
					width(i, true) = typeWidth;
					break;
					
				default: llvm_unreachable("unknown binary operator");
			}
		}
		
		void visitPHINode(PHINode& i)
		{
			// that's an approximation, we'll probably need to refine this
			width(i) = dl.getTypeSizeInBits(i.getType());
		}
		
		void visitInstruction(Instruction& i)
		{
			assert(i.use_begin() == i.use_end());
		}
		
#pragma mark -
		uint16_t& width(Value& v, bool requiresTopBits = false)
		{
			if (requiresTopBits)
			{
				this->requiresTopBits.insert(&v);
			}
			
			return bitWidths[&v];
		}
		
		uint16_t get_width(Value* v)
		{
			auto iter = bitWidths.find(v);
			if (iter == bitWidths.end())
			{
				if (auto constant = dyn_cast<Constant>(v))
				{
					visitConstant(*constant);
				}
				return bitWidths[v];
			}
			return iter->second;
		}
		
		uint16_t get_width(Value& v)
		{
			return get_width(&v);
		}
	};
	
	struct IntegerDemotionPass : public FunctionPass
	{
		static char ID;
		const DataLayout* dl;
		
		IntegerDemotionPass() : FunctionPass(ID)
		{
		}
		
		virtual bool doInitialization(Module& m) override
		{
			dl = &m.getDataLayout();
			return false;
		}
		
		virtual bool runOnFunction(Function& f) override
		{
			bool modified = false;
			IntegerDemotionAnalysis analysis(*dl);
			analysis.visit(f);
			for (Value* store : analysis.stores)
			{
				analysis.dump(store);
			}
			
			return modified;
		}
	};
	
	char IntegerDemotionPass::ID = 0;
	static RegisterPass<IntegerDemotionPass> intDemote("int-demote", "Demote large integers that are only used as smaller integers", false, false);
}

FunctionPass* createIntegerDemotionPass()
{
	return new IntegerDemotionPass;
}
