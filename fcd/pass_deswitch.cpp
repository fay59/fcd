//
// pass_deswitch.cpp
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

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>

using namespace llvm;

namespace
{
	struct SwitchRemover : public FunctionPass
	{
		static char ID;
		
		SwitchRemover() : FunctionPass(ID)
		{
		}
		
		virtual const char* getPassName() const override
		{
			return "Switch remover";
		}
		
		virtual bool runOnFunction(Function& fn) override
		{
			bool changed = false;
			for (BasicBlock& bb : fn)
			{
				if (auto term = dyn_cast<SwitchInst>(bb.getTerminator()))
				{
					changed = runOnSwitch(term);
				}
			}
			return changed;
		}
		
		bool runOnSwitch(SwitchInst* inst)
		{
			BasicBlock* parent = inst->getParent();
			BasicBlock* terminate = parent;
			
			for (auto& switchCase : inst->cases())
			{
				BasicBlock* cascade = BasicBlock::Create(inst->getContext(), "", terminate->getParent());
				BasicBlock* successor = switchCase.getCaseSuccessor();
				fixPhiNodes(successor, parent, terminate);
				
				auto cmp = ICmpInst::Create(CmpInst::ICmp, ICmpInst::ICMP_EQ, inst->getCondition(), switchCase.getCaseValue(), "", terminate);
				BranchInst::Create(successor, cascade, cmp, terminate);
				terminate = cascade;
			}
			
			BasicBlock* defaultDest = inst->getDefaultDest();
			BranchInst::Create(defaultDest, terminate);
			fixPhiNodes(defaultDest, parent, terminate);
			
			inst->eraseFromParent();
			return true;
		}
		
		void fixPhiNodes(BasicBlock* destBB, BasicBlock* oldPred, BasicBlock* newPred)
		{
			for (auto iter = destBB->begin(); auto phi = dyn_cast<PHINode>(iter); ++iter)
			{
				for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i)
				{
					if (phi->getIncomingBlock(i) == oldPred)
					{
						phi->setIncomingBlock(i, newPred);
					}
				}
			}
		}
	};
	
	char SwitchRemover::ID = 0;
	
	RegisterPass<SwitchRemover> condSimp("removeswitches", "Transform switch terminators into cascading if-else nodes");
}

FunctionPass* createSwitchRemoverPass()
{
	return new SwitchRemover;
}
