//
// pass_conditions.cpp
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

#include "passes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/PatternMatch.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace llvm::PatternMatch;
using namespace std;

namespace
{
	Value* matchGetSignFlag(Value& value)
	{
		Value* from = &value;
		while (auto asCast = dyn_cast<CastInst>(from))
		{
			from = asCast->getOperand(0);
		}
		
		Value* operand = nullptr;
		ConstantInt* shiftAmount = nullptr;
		if (match(from, m_LShr(m_Value(operand), m_ConstantInt(shiftAmount))))
		if (operand->getType()->getIntegerBitWidth() == shiftAmount->getLimitedValue() + 1)
		{
			return operand;
		}
		return nullptr;
	}
	
	bool isXorSub(BinaryOperator& xorInst, Value*& left, Value*& right)
	{
		Value* xorOp = nullptr;
		auto sub = m_Sub(m_Value(left), m_Value(right));
		if (match(&xorInst, m_Xor(m_Value(xorOp), sub)) && xorOp == left)
		{
			return true;
		}
		return match(&xorInst, m_Xor(sub, m_Value(xorOp))) && xorOp == left;
	}
	
	bool isOverflowTest(Value& value, Value*& a, Value*& b)
	{
		// %0 = sub %a, %b
		// %1 = xor %a, %b
		// %2 = xor %a, %0
		// %3 = and %1, %2
		
		auto xorOp = Instruction::Xor;
		BinaryOperator* left = nullptr;
		BinaryOperator* right = nullptr;
		if (match(&value, m_And(m_BinOp(left), m_BinOp(right))) && left->getOpcode() == xorOp && right->getOpcode() == xorOp)
		{
			Value* subLeft = nullptr;
			Value* subRight = nullptr;
			BinaryOperator* xorValues = nullptr;
			if (isXorSub(*left, subLeft, subRight))
			{
				xorValues = right;
			}
			else if (isXorSub(*right, subLeft, subRight))
			{
				xorValues = left;
			}
			
			if (xorValues != nullptr)
			{
				auto op0 = xorValues->getOperand(0);
				auto op1 = xorValues->getOperand(1);
				if ((op0 == subLeft && op1 == subRight) || (op0 == subRight && op1 == subLeft))
				{
					a = subLeft;
					b = subRight;
					return true;
				}
			}
		}
		return false;
	}
	
	void resizeComparison(ICmpInst& icmp, ICmpInst::Predicate pred, unsigned bits, Value* left, Value* right)
	{
		auto intTy = Type::getIntNTy(icmp.getContext(), bits);
		auto compareLeft = CastInst::Create(CastInst::Trunc, left, intTy, "", &icmp);
		auto compareRight = CastInst::Create(CastInst::Trunc, right, intTy, "", &icmp);
		auto newComp = ICmpInst::Create(Instruction::ICmp, pred, compareLeft, compareRight, "", &icmp);
		icmp.replaceAllUsesWith(newComp);
	}
	
	void resizeComparison(ICmpInst& icmp, ICmpInst::Predicate pred, const APInt& mask, Value* left, Value* right)
	{
		unsigned bits = mask.getActiveBits();
		if (mask.trunc(bits).isAllOnesValue())
		{
			resizeComparison(icmp, pred, bits, left, right);
		}
	}
	
	struct ConditionSimplification final : public FunctionPass
	{
		static char ID;
		
		ConditionSimplification() : FunctionPass(ID)
		{
		}
		
		virtual bool runOnFunction(Function& fn) override
		{
			bool result = false;
			for (auto& bb : fn)
			{
				result |= runOnBasicBlock(bb);
			}
			return result;
		}
		
		bool runOnBasicBlock(BasicBlock& bb)
		{
			bool result = false;
			// Attempt to remove uses of usub_with_overflow by replacig its bool element with icmp ult.
			for (auto& inst : bb)
			{
				auto opcode = inst.getOpcode();
				if (opcode == Instruction::Call)
				{
					if (auto intrin = dyn_cast<IntrinsicInst>(&inst))
					if (intrin->getIntrinsicID() == Intrinsic::usub_with_overflow)
					{
						result |= replaceUsubWithOverflow(*intrin);
					}
				}
				else if (opcode == Instruction::ICmp)
				{
					auto& icmp = cast<ICmpInst>(inst);
					auto pred = icmp.getPredicate();
					if (pred == ICmpInst::ICMP_EQ || pred == ICmpInst::ICMP_NE)
					{
						if (auto left = matchGetSignFlag(*icmp.getOperand(0)))
						{
							if (auto right = matchGetSignFlag(*icmp.getOperand(1)))
							{
								Value* compareLeft = nullptr;
								Value* compareRight = nullptr;
								Value* testMatch = nullptr;
								if (isOverflowTest(*left, compareLeft, compareRight))
								{
									testMatch = right;
								}
								else if (isOverflowTest(*right, compareLeft, compareRight))
								{
									testMatch = left;
								}
								
								if (testMatch != nullptr && match(testMatch, m_Sub(m_Value(compareLeft), m_Value(compareRight))))
								{
									auto newPred = pred == ICmpInst::ICMP_EQ ? ICmpInst::ICMP_SGE : ICmpInst::ICMP_SLE;
									auto newComp = ICmpInst::Create(Instruction::ICmp, newPred, compareLeft, compareRight, "", &icmp);
									icmp.replaceAllUsesWith(newComp);
									result = true;
								}
							}
						}
						else if (match(icmp.getOperand(1), m_ConstantInt<0>()))
						{
							Value* left = nullptr;
							Value* right = nullptr;
							ConstantInt* intSize = nullptr;
							if (match(icmp.getOperand(0), m_And(m_Sub(m_Value(left), m_Value(right)), m_ConstantInt(intSize))))
							{
								resizeComparison(icmp, pred, intSize->getValue(), left, right);
							}
						}
					}
					else if (pred == ICmpInst::ICMP_UGT)
					{
						Value* subLeft = nullptr;
						Value* subRight = nullptr;
						ConstantInt* right = nullptr;
						if (match(&icmp, m_ICmp(pred, m_Sub(m_Value(subLeft), m_Value(subRight)), m_ConstantInt(right))))
						{
							resizeComparison(icmp, ICmpInst::ICMP_ULT, right->getValue(), subLeft, subRight);
						}
					}
					else if (pred == ICmpInst::ICMP_ULT)
					{
						Value* subLeft = nullptr;
						Value* subRight = nullptr;
						ConstantInt* right = nullptr;
						if (match(&icmp, m_ICmp(pred, m_Sub(m_Value(subLeft), m_Value(subRight)), m_ConstantInt(right))))
						{
							const auto& compareTo = right->getValue();
							if (compareTo.isPowerOf2())
							{
								resizeComparison(icmp, ICmpInst::ICMP_UGE, compareTo.getActiveBits() - 1, subLeft, subRight);
							}
						}
					}
				}
				else if (opcode == Instruction::LShr)
				{
					if (auto signFlagOf = matchGetSignFlag(inst))
					if (auto xorInst = dyn_cast<BinaryOperator>(signFlagOf))
					if (xorInst->getOpcode() == Instruction::Xor)
					{
						auto left = xorInst->getOperand(0);
						auto right = xorInst->getOperand(1);
						
						Value* compareLeft = nullptr;
						Value* compareRight = nullptr;
						Value* presumedSub = nullptr;
						if (isOverflowTest(*left, compareLeft, compareRight))
						{
							presumedSub = right;
						}
						else if (isOverflowTest(*right, compareLeft, compareRight))
						{
							presumedSub = left;
						}
						
						if (presumedSub != nullptr && match(presumedSub, m_Sub(m_Value(compareLeft), m_Value(compareRight))))
						{
							auto icmp = ICmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_SLT, compareLeft, compareRight, "", &inst);
							auto zext = new ZExtInst(icmp, inst.getType(), "", &inst);
							inst.replaceAllUsesWith(zext);
							result = true;
						}
					}
				}
			}
			return result;
		}
		
		bool replaceUsubWithOverflow(IntrinsicInst& inst)
		{
			// This doesn't actually remove the usub_with_overflow, it merely replaces uses of its
			// boolean return value.
			bool result = false;
			for (auto& use : inst.uses())
			{
				if (auto extract = dyn_cast<ExtractValueInst>(use.getUser()))
				if (*extract->idx_begin() == 1)
				{
					assert(extract->getNumIndices() == 1);
					auto icmp = ICmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_ULT, inst.getOperand(0), inst.getOperand(1), "", extract);
					extract->replaceAllUsesWith(icmp);
					result = true;
				}
				
			}
			return result;
		}
	};
	
	char ConditionSimplification::ID = 0;
	
	RegisterPass<ConditionSimplification> condSimp("simplifyconditions", "Simplify flag-based x86 conditionals");
}

FunctionPass* createConditionSimplificationPass()
{
	return new ConditionSimplification;
}
