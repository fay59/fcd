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
	Value* unwrapCast(Value* maybeCast)
	{
		if (auto castInst = dyn_cast<CastInst>(maybeCast))
		{
			return castInst->getOperand(0);
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
			return false;
		}
		
		bool handleLogicalShiftRight(BinaryOperator& shiftRight)
		{
			uint64_t twoPower;
			uint64_t multiplier;
			Value* operand;
			if (match(&shiftRight, m_LShr(m_Mul(m_Value(operand), m_ConstantInt(multiplier)), m_ConstantInt(twoPower))))
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
			return false;
		}
		
		bool handleAdd(BinaryOperator& addInst)
		{
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
