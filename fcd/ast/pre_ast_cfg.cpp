//
// pre_ast_cfg.cpp
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

#include "ast_context.h"
#include "pre_ast_cfg.h"
#include "pre_ast_cfg_traits.h"

#include <llvm/Analysis/RegionInfoImpl.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/GraphWriter.h>
#include <llvm/Support/raw_ostream.h>

using namespace llvm;
using namespace std;

void PreAstBasicBlockEdge::setTo(PreAstBasicBlock& newTo)
{
	for (auto iter = to->predecessors.begin(); iter != to->predecessors.end(); ++iter)
	{
		if (*iter == this)
		{
			to->predecessors.erase(iter);
			newTo.predecessors.push_back(this);
			to = &newTo;
			return;
		}
	}
	
	llvm_unreachable("Edge not found in predecessor!");
}

void PreAstBasicBlock::printAsOperand(llvm::raw_ostream& os, bool printType)
{
	if (block == nullptr)
	{
		os << "(synthesized block)";
	}
	else
	{
		block->printAsOperand(os, printType);
	}
}

PreAstContext::PreAstContext(AstContext& ctx)
: ctx(ctx)
{
}

void PreAstContext::generateBlocks(Function& fn)
{
	for (BasicBlock& bb : fn)
	{
		PreAstBasicBlock& preAstBB = createBlock();
		preAstBB.block = &bb;
		blockMapping.insert({&bb, &preAstBB});
		
		// Create block statement
		SequenceStatement* seq = ctx.sequence();
		for (Instruction& inst : bb)
		{
			if (auto statement = ctx.statementFor(inst))
			{
				seq->pushBack(statement);
			}
		}
		preAstBB.blockStatement = seq;
	}
	
	for (BasicBlock& bbRef : fn)
	{
		BasicBlock* bb = &bbRef;
		PreAstBasicBlock& preAstBB = *blockMapping.at(bb);
		
		for (BasicBlock* pred : predecessors(bb))
		{
			// Insert PHI assignments
			for (auto phiIter = pred->begin(); auto phi = dyn_cast<PHINode>(phiIter); ++phiIter)
			{
				auto assignment = ctx.phiAssignment(*phi, *phi->getIncomingValueForBlock(pred));
				preAstBB.blockStatement = ctx.append(preAstBB.blockStatement, assignment);
			}
			
			// Compute edge condition and create edge
			Expression* edgeCondition;
			if (auto branch = dyn_cast<BranchInst>(pred->getTerminator()))
			{
				if (branch->isConditional())
				{
					Expression* branchCondition = ctx.expressionFor(*branch->getCondition());
					if (bb == branch->getSuccessor(0))
					{
						edgeCondition = branchCondition;
					}
					else
					{
						assert(bb == branch->getSuccessor(1));
						edgeCondition = ctx.negate(branchCondition);
					}
				}
				else
				{
					edgeCondition = ctx.expressionForTrue();
				}
			}
			else if (auto switchInst = dyn_cast<SwitchInst>(pred->getTerminator()))
			{
				edgeCondition = ctx.expressionForFalse();
				Expression* defaultCondition = nullptr;
				if (bb == switchInst->getDefaultDest())
				{
					defaultCondition = ctx.expressionForFalse();
				}
				
				Expression* testVariable = ctx.expressionFor(*switchInst->getCondition());
				for (const auto& switchCase : switchInst->cases())
				{
					Value* caseValue = switchInst->getOperand(switchCase.getCaseIndex());
					BasicBlock* dest = cast<BasicBlock>(switchInst->getOperand(switchCase.getSuccessorIndex()));
					Expression* caseCondition = nullptr;
					if (dest == bb || defaultCondition != nullptr)
					{
						Expression* caseExpr = ctx.expressionFor(*caseValue);
						caseCondition = ctx.nary(NAryOperatorExpression::Equal, testVariable, caseExpr);
					}
					if (dest == bb)
					{
						edgeCondition = ctx.nary(NAryOperatorExpression::ShortCircuitOr, edgeCondition, caseCondition);
					}
					if (defaultCondition != nullptr)
					{
						defaultCondition = ctx.nary(NAryOperatorExpression::ShortCircuitOr, defaultCondition, caseCondition);
					}
				}
				if (defaultCondition != nullptr)
				{
					edgeCondition = ctx.nary(NAryOperatorExpression::ShortCircuitOr, edgeCondition, ctx.negate(defaultCondition));
				}
			}
			else
			{
				llvm_unreachable("Unknown terminator with successors!");
			}
			
			PreAstBasicBlock& predAstBB = *blockMapping.at(pred);
			PreAstBasicBlockEdge& edge = createEdge(predAstBB, preAstBB, *edgeCondition);
			preAstBB.predecessors.push_back(&edge);
			predAstBB.successors.push_back(&edge);
		}
	}
}

PreAstBasicBlock& PreAstContext::createRedirectorBlock(ArrayRef<PreAstBasicBlockEdge*> redirectedEdgeList)
{
	PreAstBasicBlock& newBlock = createBlock();
	newBlock.sythesizedVariable = ctx.assignable(ctx.getIntegerType(false, 32), "dispatch");
	
	SmallDenseMap<PreAstBasicBlock*, Expression*> caseValues;
	for (auto edge : redirectedEdgeList)
	{
		auto iter = caseValues.find(edge->to);
		if (iter == caseValues.end())
		{
			Expression* numericConstant = ctx.numeric(ctx.getIntegerType(false, 32), caseValues.size());
			iter = caseValues.insert({edge->to, numericConstant}).first;
		}
		
		Statement* assignment = ctx.expr(ctx.nary(NAryOperatorExpression::Assign, newBlock.sythesizedVariable, iter->second));
		edge->from->blockStatement = ctx.append(edge->from->blockStatement, assignment);
		
		Expression* condition = ctx.nary(NAryOperatorExpression::Equal, newBlock.sythesizedVariable, iter->second);
		PreAstBasicBlockEdge& newEdge = createEdge(newBlock, *edge->to, *condition);
		newEdge.from->successors.push_back(&newEdge);
		newEdge.to->predecessors.push_back(&newEdge);
		edge->setTo(newBlock);
	}
	return newBlock;
}

void PreAstContext::view() const
{
	ViewGraph(const_cast<PreAstContext*>(this), "Pre-AST Basic Block Graph");
}

PreAstRegionInfo::PreAstRegionInfo()
{
}

void PreAstRegionInfo::recalculate(FuncT& function, DomTreeT* domTree, PostDomTreeT* postDomTree, DomFrontierT* dominanceFrontier)
{
	DT = domTree;
	PDT = postDomTree;
	DF = dominanceFrontier;
	TopLevelRegion = new RegionBase<PreAstBasicBlockRegionTraits>(function.getEntryBlock(), nullptr, this, domTree, nullptr);
	calculate(function);
}

void PreAstRegionInfo::updateStatistics(RegionT* region)
{
}
