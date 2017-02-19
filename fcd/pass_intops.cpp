//
// pass_intops.cpp
// Copyright (C) 2017 Félix Cloutier.
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

#include <llvm/IR/Constants.h>
#include <llvm/IR/PatternMatch.h>

using namespace llvm;
using namespace llvm::PatternMatch;
using namespace std;

namespace
{
	[[gnu::const]]
	Value* unwrapCast(Value* maybeCast)
	{
		while (auto castInst = dyn_cast<CastInst>(maybeCast))
		{
			maybeCast = castInst->getOperand(0);
		}
		return maybeCast;
	}
	
	bool replaceWithDivision(Instruction& insertionPoint, Value* left, uint64_t denom, bool signedDiv = true)
	{
		auto denominator = ConstantInt::get(left->getType(), denom);
		Instruction* result = signedDiv
			? BinaryOperator::CreateSDiv(left, denominator, "", &insertionPoint)
			: BinaryOperator::CreateUDiv(left, denominator, "", &insertionPoint);
		if (result->getType() != insertionPoint.getType())
		{
			assert(insertionPoint.getType()->getIntegerBitWidth() > result->getType()->getIntegerBitWidth());
			result = CastInst::Create(signedDiv ? CastInst::SExt : CastInst::ZExt, result, insertionPoint.getType(), "", &insertionPoint);
		}
		insertionPoint.replaceAllUsesWith(result);
		return true;
	}
	
	// Has to happen after instcombine
	struct IntOperations : public FunctionPass
	{
		static char ID;
		
		IntOperations() : FunctionPass(ID)
		{
		}
		
		virtual bool runOnFunction(Function& fn) override
		{
			bool changed = false;
			
			for (BasicBlock& bb : fn)
			{
				for (Instruction& inst : bb)
				{
					if (inst.getOpcode() == BinaryOperator::AShr)
					{
						// (Signed division by a power of two)
						auto& shiftRight = cast<BinaryOperator>(inst);
						changed |= handleArithmeticShiftRight(shiftRight);
					}
					else if (inst.getOpcode() == BinaryOperator::LShr)
					{
						auto& shiftRight = cast<BinaryOperator>(inst);
						changed |= handleLogicalShiftRight(shiftRight);
					}
					else if (inst.getOpcode() == BinaryOperator::Add)
					{
						// (Signed division by a constant)
						auto& addInst = cast<BinaryOperator>(inst);
						changed |= handleAdd(addInst);
					}
					else if (inst.getOpcode() == BinaryOperator::Sub)
					{
						auto& subInst = cast<BinaryOperator>(inst);
						changed |= handleSub(subInst);
					}
				}
			}
			
			return changed;
		}
		
		bool handleArithmeticShiftRight(BinaryOperator& shiftRight)
		{
			// Signed division by a power of two
			{
				Value* addOperand;
				Value* truncOperand;
				Value* largeShiftOperand;
				uint64_t smallShiftAmount, largeShiftAmount, mask;
				if (match(&shiftRight, m_AShr(m_Add(m_And(m_Trunc(m_Value(truncOperand)), m_ConstantInt(mask)), m_Value(addOperand)), m_ConstantInt(smallShiftAmount))))
				if (match(unwrapCast(truncOperand), m_LShr(m_Value(largeShiftOperand), m_ConstantInt(largeShiftAmount))))
				if (unwrapCast(largeShiftOperand) == unwrapCast(addOperand))
				if (addOperand->getType()->getIntegerBitWidth() < largeShiftAmount)
				if (((mask + 1) & mask) == 0) // mask starts at least significant bit and is contiguous?
				if (__builtin_ctzll(~mask) == smallShiftAmount)
				{
					return replaceWithDivision(shiftRight, addOperand, 1ull << smallShiftAmount);
				}
			}
			
			return false;
		}
		
		bool handleLogicalShiftRight(BinaryOperator& shiftRight)
		{
			uint64_t twoPower;
			uint64_t multiplier;
			Value* operand;
			auto mulTree = m_LShr(m_Mul(m_Value(operand), m_ConstantInt(multiplier)), m_ConstantInt(twoPower));
			
			if (match(&shiftRight, mulTree))
			{
				if (twoPower < numeric_limits<double>::digits) // this would cause our verification to break down
				{
					Value* originalValue = unwrapCast(operand);
					uint64_t bitWidth = originalValue->getType()->getIntegerBitWidth();
					double denominator = static_cast<double>(1ull << twoPower) / multiplier;
					double ceiled = ceil(denominator);
					if (1 / (ceiled - denominator) >= (1ull << bitWidth) / ceiled)
					{
						return replaceWithDivision(shiftRight, originalValue, static_cast<uint64_t>(ceiled), false);
					}
				}
			}
			else
			{
				// With a as the operand and r as the result, we are trying to match:
				//  m = (a * C) >> Z
				//  r = (m + ((a - m) >> Y)) >> X
				// Given this, we also know that:
				//  r = a / D
				// We just need to isolate D:
				//  D = (1 << X+Y+Z) / (C * ((1 << Y) - 1) + (1 << Z)
				// and make sure that it is correct in the domain that the division targets.
				uint64_t x, y;
				Value* subtraction;
				Value* originalValue;
				Value* mulTreeValue;
				Value* m;
				if (match(&shiftRight, m_LShr(m_Add(m_Value(mulTreeValue), m_LShr(m_Value(subtraction), m_ConstantInt(y))), m_ConstantInt(x))))
				if (match(mulTreeValue, mulTree) && match(unwrapCast(subtraction), m_Sub(m_Value(originalValue), m_Value(m))))
				if (unwrapCast(operand) == unwrapCast(originalValue) && unwrapCast(m) == mulTreeValue)
				{
					Value* originalValue = unwrapCast(operand);
					uint64_t bitWidth = originalValue->getType()->getIntegerBitWidth();
					double denominator = static_cast<double>(1ull << (x + y + twoPower)) / (multiplier * ((1ull << y) - 1) + (1ull << twoPower));
					double ceiled = ceil(denominator);
					if (1 / (ceiled - denominator) >= (1ull << bitWidth) / ceiled)
					{
						return replaceWithDivision(shiftRight, originalValue, static_cast<uint64_t>(ceiled), false);
					}
				}
			}
			return false;
		}
		
		bool handleAdd(BinaryOperator& addInst)
		{
			// Unsigned remainder
			{
				Value* addRight;
				Value* divLeft;
				Value* andOperand;
				uint64_t denominator;
				uint64_t mask;
				uint64_t multiplier;
				if (match(&addInst, m_Add(m_Mul(m_And(m_Value(andOperand), m_ConstantInt(mask)), m_ConstantInt(multiplier)), m_Value(addRight))))
				if (match(unwrapCast(andOperand), m_UDiv(m_Value(divLeft), m_ConstantInt(denominator))))
				if (addRight == divLeft)
				{
					uint64_t maxValue = 1ull << addRight->getType()->getIntegerBitWidth();
					if (multiplier == maxValue - denominator && maxValue / denominator <= mask)
					{
						denominator *= 1 << __builtin_ctzll(mask);
						auto constantDenominator = ConstantInt::get(divLeft->getType(), denominator);
						auto urem = BinaryOperator::CreateURem(divLeft, constantDenominator, "", &addInst);
						addInst.replaceAllUsesWith(urem);
						return true;
					}
				}
			}
			
			// Signed division
			{
				Value* truncOperands[2];
				Value* shiftOperands[2];
				Value* multipliedValue;
				uint64_t smallShiftAmount, largeShiftAmount, multiplier;
				
				if (match(&addInst, m_Add(m_Value(truncOperands[0]), m_Value(truncOperands[1]))))
				if (match(unwrapCast(truncOperands[0]), m_LShr(m_Value(shiftOperands[0]), m_ConstantInt(smallShiftAmount))) || match(unwrapCast(truncOperands[0]), m_AShr(m_Value(shiftOperands[0]), m_ConstantInt(smallShiftAmount))))
				if (match(unwrapCast(truncOperands[1]), m_LShr(m_Value(shiftOperands[1]), m_ConstantInt(largeShiftAmount))) || match(unwrapCast(truncOperands[1]), m_AShr(m_Value(shiftOperands[1]), m_ConstantInt(largeShiftAmount))))
				if (shiftOperands[0] == shiftOperands[1])
				{
					uint64_t shiftWidth = shiftOperands[0]->getType()->getIntegerBitWidth();
					if (shiftWidth == largeShiftAmount + 1)
					{
						if (match(shiftOperands[0], m_Mul(m_Value(multipliedValue), m_ConstantInt(multiplier))))
						{
							Value* originalValue = unwrapCast(multipliedValue);
							uint64_t originalBitWidth = originalValue->getType()->getIntegerBitWidth();
							if (originalBitWidth <= smallShiftAmount)
							{
								double denominator = static_cast<double>(1ull << smallShiftAmount) / multiplier;
								double ceiled = ceil(denominator);
								uint64_t resultWidth = shiftWidth - smallShiftAmount - 1;
								if (1 / (ceiled - denominator) >= (1ull << resultWidth) / ceiled)
								{
									return replaceWithDivision(addInst, originalValue, static_cast<uint64_t>(ceiled));
								}
							}
						}
						else
						{
							Value* originalValue[2];
							uint64_t widthShift;
							if (match(shiftOperands[0], m_Add(m_Trunc(m_LShr(m_Mul(m_SExt(m_Value(originalValue[0])), m_ConstantInt(multiplier)), m_ConstantInt(widthShift))), m_Value(originalValue[1]))))
							if (originalValue[0] == originalValue[1] && widthShift == originalValue[0]->getType()->getIntegerBitWidth())
							{
								uint64_t multiplierMask = (1ull << widthShift) - 1;
								double denominator = static_cast<double>(1ull << (widthShift + smallShiftAmount)) / (multiplier & multiplierMask);
								double ceiled = ceil(denominator);
								uint64_t resultWidth = widthShift - smallShiftAmount - 1;
								if (1 / (ceiled - denominator) >= (1ull << resultWidth) / ceiled)
								{
									return replaceWithDivision(addInst, originalValue[0], static_cast<uint64_t>(ceiled));
								}
							}
						}
					}
				}
			}
			return false;
		}
		
		bool handleSub(BinaryOperator& subInst)
		{
			return false;
		}
	};
	
	char IntOperations::ID = 0;
	
	RegisterPass<IntOperations> intOps("intops", "Simplify integer operations");
}
