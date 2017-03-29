//
// pass_conditions.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "passes.h"

#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/PatternMatch.h>

using namespace llvm;
using namespace llvm::PatternMatch;
using namespace std;

namespace
{
	Value* getOriginalValue(Value& value)
	{
		Value* from = &value;
		while (auto asCast = dyn_cast<CastInst>(from))
		{
			from = asCast->getOperand(0);
		}
		return from;
	}
	
	bool isSameLowerBits(Value* a, Value* b)
	{
		return getOriginalValue(*a) == getOriginalValue(*b);
	}
	
	struct Subtraction
	{
		Value* left;
		Value* right;
		unsigned bitness;
		
		Subtraction(Value* left, Value* right, unsigned bitness)
		: left(left), right(right), bitness(bitness)
		{
		}
		
		bool isSame(Value* l, Value* r, unsigned b)
		{
			if (b == bitness)
			{
				return (isSameLowerBits(l, left) && isSameLowerBits(r, right))
					|| (isSameLowerBits(r, left) && isSameLowerBits(l, right));
			}
			return false;
		}
	};
	
	bool isSameSub(unique_ptr<Subtraction>& sub, Value* a, Value* b, unsigned bitness)
	{
		if (sub)
		{
			return sub->isSame(a, b, bitness);
		}
		else
		{
			if (auto constant = dyn_cast<ConstantInt>(b))
			{
				// check if a is (v + constant) too because LLVM will do a lot of constant folding
				Value* rootValue = nullptr;
				ConstantInt* constantAdd = nullptr;
				if (match(a, m_Add(m_Value(rootValue), m_ConstantInt(constantAdd))))
				{
					a = rootValue;
					b = ConstantInt::get(rootValue->getType(), constant->getValue() - constantAdd->getValue());
				}
			}
			sub.reset(new Subtraction(a, b, bitness));
			return true;
		}
	}
	
	bool matchSignFlag(Value& value, unique_ptr<Subtraction>& sub)
	{
		auto original = getOriginalValue(value);
		Value* one = nullptr;
		if (match(original, m_And(m_Value(original), m_Value(one))))
		if (match(getOriginalValue(*one), m_ConstantInt<1>()))
		{
			original = getOriginalValue(*original);
		}
		
		Value* a = nullptr;
		Value* b = nullptr;
		Value* operand = nullptr;
		ConstantInt* shiftAmount = nullptr;
		if (match(original, m_LShr(m_Value(operand), m_ConstantInt(shiftAmount))))
		{
			auto bitness = static_cast<unsigned>(shiftAmount->getLimitedValue()) + 1;
			if (match(operand, m_Sub(m_Value(a), m_Value(b))))
			{
				return isSameSub(sub, a, b, bitness);
			}
			else
			{
				ConstantInt* constantRight = nullptr;
				if (match(operand, m_Add(m_Value(a), m_ConstantInt(constantRight))))
				{
					Type* constantType = constantRight->getType();
					Constant* negated = ConstantInt::get(constantType, -constantRight->getValue());
					return isSameSub(sub, a, negated, constantType->getIntegerBitWidth());
				}
			}
		}
		else
		{
			ICmpInst::Predicate pred;
			if (match(original, m_ICmp(pred, m_Sub(m_Value(a), m_Value(b)), m_Zero())) && pred == ICmpInst::ICMP_SLT)
			{
				return isSameSub(sub, a, b, a->getType()->getIntegerBitWidth());
			}
		}
		return false;
	}
	
	bool matchOverflowFlag(Value& value, unique_ptr<Subtraction>& sub)
	{
		auto original = getOriginalValue(value);
		if (auto extract = dyn_cast<ExtractValueInst>(original))
		if (auto intrin = dyn_cast<IntrinsicInst>(extract->getAggregateOperand()))
		if (intrin->getIntrinsicID() == Intrinsic::ssub_with_overflow)
		{
			auto indices = extract->getIndices();
			if (indices.size() == 1 && indices[0] == 1)
			{
				Value* a = intrin->getArgOperand(0);
				return isSameSub(sub, a, intrin->getArgOperand(1), a->getType()->getIntegerBitWidth());
			}
		}
		return false;
	}
	
	unique_ptr<Subtraction> matchOverflowSignFlag(Value& xorLeft, Value& xorRight)
	{
		unique_ptr<Subtraction> sub;
		if (matchOverflowFlag(xorLeft, sub))
		{
			if (matchSignFlag(xorRight, sub))
			{
				return sub;
			}
		}
		else if (matchOverflowFlag(xorRight, sub))
		{
			if (matchSignFlag(xorLeft, sub))
			{
				return sub;
			}
		}
		return nullptr;
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
			for (auto& inst : bb)
			{
				Value* arg0 = nullptr;
				Value* arg1 = nullptr;
				if (match(&inst, m_Intrinsic<Intrinsic::usub_with_overflow>(m_Value(arg0), m_Value(arg1))))
				{
					for (auto user : inst.users())
					{
						if (auto extract = dyn_cast<ExtractValueInst>(user))
						{
							auto indices = extract->getIndices();
							if (indices.size() == 1 && indices[0] == 1)
							{
								auto icmp = ICmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_ULT, arg0, arg1, "", &inst);
								extract->replaceAllUsesWith(icmp);
							}
						}
					}
				}
				else
				{
					Instruction* comparison = nullptr;
					ICmpInst::Predicate pred;
					if (match(&inst, m_Xor(m_Value(arg0), m_Value(arg1))))
					{
						if (unique_ptr<Subtraction> sub = matchOverflowSignFlag(*arg0, *arg1))
						{
							comparison = ICmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_SLT, sub->left, sub->right, "", &inst);
						}
					}
					else if (match(&inst, m_ICmp(pred, m_Value(arg0), m_Value(arg1))))
					{
						if (pred == ICmpInst::ICMP_EQ || pred == ICmpInst::ICMP_NE)
						if (unique_ptr<Subtraction> sub = matchOverflowSignFlag(*arg0, *arg1))
						{
							CmpInst::Predicate comparisonPred;
							if (pred == ICmpInst::ICMP_NE)
							{
								comparisonPred = ICmpInst::ICMP_SLT;
							}
							else if (pred == ICmpInst::ICMP_EQ)
							{
								comparisonPred = ICmpInst::ICMP_SGE;
							}
							else
							{
								continue;
							}
							comparison = ICmpInst::Create(Instruction::ICmp, comparisonPred, sub->left, sub->right, "", &inst);
						}
					}
					else
					{
						// For some time, LLVM has "simplified" instructions that are almost signed comparisons
						// with zero into ((var >> 31) | (var == 0)). This tests against this very specific
						// pattern.
						uint64_t shiftAmount;
						Value* shiftedValue;
						Value* testedValue;
						if (match(&inst, m_Or(m_LShr(m_Value(shiftedValue), m_ConstantInt(shiftAmount)), m_ZExt(m_ICmp(pred, m_Value(testedValue), m_ConstantInt<0>())))))
						if (shiftedValue == testedValue)
						if (shiftAmount == shiftedValue->getType()->getIntegerBitWidth() - 1)
						{
							auto zero = ConstantInt::get(shiftedValue->getType(), 0);
							comparison = ICmpInst::Create(Instruction::ICmp, CmpInst::ICMP_SLE, shiftedValue, zero, "", &inst);
						}
					}
					
					if (comparison != nullptr)
					{
						Instruction* resultInst = inst.getType() != comparison->getType()
							? (Instruction*)CastInst::Create(CastInst::ZExt, comparison, inst.getType(), "", &inst)
							: (Instruction*)comparison;
						inst.replaceAllUsesWith(resultInst);
					}
				}
			}
			return result;
		}
	};
	
	char ConditionSimplification::ID = 0;
	
	RegisterPass<ConditionSimplification> condSimp("simplifyconditions", "Simplify flag-based conditionals");
}
