//
// pass_intnarrowing.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "passes.h"

#include <llvm/Analysis/DemandedBits.h>
#include <llvm/IR/Constants.h>

#include <unordered_map>
#include <unordered_set>

using namespace llvm;
using namespace std;

namespace
{
	bool isMod2Equivalent(BinaryOperator::BinaryOps operation)
	{
		switch (operation)
		{
			case BinaryOperator::UDiv:
			case BinaryOperator::SDiv:
			case BinaryOperator::URem:
			case BinaryOperator::SRem:
			case BinaryOperator::Shl:
			case BinaryOperator::LShr:
			case BinaryOperator::AShr:
				return false;
				
			default: return true;
		}
	}
	
	struct IntNarrowing : public FunctionPass
	{
		static char ID;
		
		Function* currentFunction;
		unordered_map<Value*, SmallDenseMap<unsigned, Instruction*, 8>> resized;
		
		IntNarrowing() : FunctionPass(ID)
		{
		}
		
		virtual StringRef getPassName() const override
		{
			return "Narrow Integers";
		}
		
		virtual void getAnalysisUsage(AnalysisUsage& au) const override
		{
			au.addRequired<DemandedBitsWrapperPass>();
		}
		
		Value* narrowDown(Value* thatValue, unsigned size)
		{
			auto valueSize = thatValue->getType()->getIntegerBitWidth();
			if (valueSize == size)
			{
				return thatValue;
			}
			
			auto& valueMap = resized[thatValue];
			auto& value = valueMap[size];
			if (value == nullptr)
			{
				auto binOp = dyn_cast<BinaryOperator>(thatValue);
				if (binOp != nullptr && isMod2Equivalent(binOp->getOpcode()))
				{
					Value* left = narrowDown(binOp->getOperand(0), size);
					Value* right = narrowDown(binOp->getOperand(1), size);
					value = BinaryOperator::Create(binOp->getOpcode(), left, right, "", binOp);
				}
				else
				{
					assert(valueSize > size);
					Type* truncatedType = Type::getIntNTy(thatValue->getContext(), size);
					Instruction* location = nullptr;
					if (auto valueAsPhi = dyn_cast<PHINode>(thatValue))
					{
						location = &*valueAsPhi->getParent()->getFirstInsertionPt();
					}
					else if (auto valueAsInst = dyn_cast<Instruction>(thatValue))
					{
						location = valueAsInst->getNextNode();
					}
					else
					{
						location = &*currentFunction->getEntryBlock().getFirstInsertionPt();
					}
					value = CastInst::Create(Instruction::Trunc, thatValue, truncatedType, "", location);
				}
			}
			return value;
		}
		
		virtual bool runOnFunction(Function& fn) override
		{
			resized.clear();
			currentFunction = &fn;
			DemandedBits& db = getAnalysis<DemandedBitsWrapperPass>().getDemandedBits();
			
			for (BasicBlock& bb : fn)
			{
				for (Instruction& inst : bb)
				{
					if (auto binOp = dyn_cast<BinaryOperator>(&inst))
					if (binOp->getType()->isIntegerTy())
					{
						unsigned typeBits = binOp->getType()->getIntegerBitWidth();
						unsigned activeBits = typeBits;
						if (binOp->getOpcode() == BinaryOperator::And)
						{
							if (auto constantMask = dyn_cast<ConstantInt>(binOp->getOperand(1)))
							{
								activeBits = constantMask->getValue().getActiveBits();
							}
						}
						else
						{
							activeBits = db.getDemandedBits(binOp).getActiveBits();
						}
						
						if (activeBits < typeBits && activeBits > 0)
						{
							narrowDown(binOp, activeBits);
						}
					}
				}
			}
			
			for (auto& pair : resized)
			{
				if (auto key = dyn_cast<Instruction>(pair.first))
				{
					auto& otherSizes = pair.second;
					if (otherSizes.size() == 1)
					{
						auto toEnlarge = otherSizes.begin()->second;
						auto type = key->getType();
						CastInst* enlarged = CastInst::Create(Instruction::ZExt, toEnlarge, type);
						enlarged->insertAfter(toEnlarge);
						
						// replace almost all uses with
						for (Use& use : key->uses())
						{
							auto user = use.getUser();
							if (user != toEnlarge && resized.count(user) == 0)
							{
								use.set(enlarged);
							}
						}
					}
				}
			}
			
			return resized.size() > 0;
		}
	};
	
	char IntNarrowing::ID = 0;
	RegisterPass<IntNarrowing> intNarrowing("intnarrowing", "Narrow down integer types to their used bits");
}
