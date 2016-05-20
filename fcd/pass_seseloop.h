//
// pass_seseloop.h
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

#ifndef pass_seseloop_h
#define pass_seseloop_h


#include <llvm/Analysis/Passes.h>
#include <llvm/IR/BasicBlock.h>

#include <unordered_map>

class SESELoop : public llvm::FunctionPass
{
	// Persistent per-function map of back-edge-destination to loop member.
	// Loops are visited in post-order and the algorithm that finds paths to sink nodes
	// doesn't run through sub-cycles. This helps identify sub-cycles and insert them as loop
	// members for larger cycles.
	std::unordered_multimap<llvm::BasicBlock*, llvm::BasicBlock*> loopMembers;
	
	void buildLoopMemberSet(llvm::BasicBlock& backEdgeDestination, const std::unordered_multimap<llvm::BasicBlock*, llvm::BasicBlock*>& destToOrigin, std::unordered_set<llvm::BasicBlock*>& members, std::unordered_set<llvm::BasicBlock*>& entries, std::unordered_set<llvm::BasicBlock*>& exits);
	bool runOnBackgoingBlock(llvm::BasicBlock& backEdgeDestination, const std::unordered_multimap<llvm::BasicBlock*, llvm::BasicBlock*>& backEdgeMap);
	
public:
	static char ID;
	SESELoop() : FunctionPass(ID)
	{
	}
	
	static std::unordered_multimap<llvm::BasicBlock*, llvm::BasicBlock*> findBackEdgeDestinations(llvm::BasicBlock& entryPoint);
	
	virtual void getAnalysisUsage(llvm::AnalysisUsage& au) const override;
	virtual bool runOnFunction(llvm::Function& fn) override;
};

llvm::FunctionPass* createSESELoopPass();

#endif /* pass_seseloop_h */
