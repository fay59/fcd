//
// pre_ast_cfg.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "ast_context.h"
#include "pre_ast_cfg.h"

#include <llvm/IR/CFG.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/GraphWriter.h>
#include <llvm/Support/raw_ostream.h>

using namespace llvm;
using namespace std;

template<>
struct DOTGraphTraits<PreAstContext*> : public DefaultDOTGraphTraits
{
	DOTGraphTraits(bool shortNames = false)
	{
	}
	
	string getNodeLabel(const PreAstBasicBlock* bb, const PreAstContext* fn)
	{
		string name;
		raw_string_ostream(name).write_hex(reinterpret_cast<uintptr_t>(bb));
		return name;
	}
};

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
	std::unordered_map<llvm::BasicBlock*, Statement*> phiInStatements;
	for (BasicBlock& bbRef : fn)
	{
		PreAstBasicBlock& preAstBB = createBlock();
		preAstBB.block = &bbRef;
		blockMapping.insert({&bbRef, &preAstBB});
		
		// Create empty block statement with just Φ nodes at first.
		Statement* seq = ctx.sequence();
		for (BasicBlock* succ : successors(&bbRef))
		{
			for (auto phiIter = succ->begin(); auto phi = dyn_cast<PHINode>(phiIter); ++phiIter)
			{
				auto assignment = ctx.phiAssignment(*phi, *phi->getIncomingValueForBlock(&bbRef));
				seq = ctx.append(seq, assignment);
			}
		}
		preAstBB.blockStatement = seq;
	}
	
	for (auto& pair : blockMapping)
	{
		BasicBlock* bb = pair.first;
		PreAstBasicBlock& preAstBB = *pair.second;
		
		// Fill up with instructions.
		SequenceStatement* seq = ctx.sequence();
		for (Instruction& inst : *bb)
		{
			if (auto statement = ctx.statementFor(inst))
			{
				seq->pushBack(statement);
			}
		}
		
		// At this point blockStatement only contains phi_in assignments, and these need to be last.
		preAstBB.blockStatement = ctx.append(seq, preAstBB.blockStatement);
		
		for (BasicBlock* pred : predecessors(bb))
		{
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
				for (auto& switchCase : switchInst->cases())
				{
					ConstantInt* caseValue = switchCase.getCaseValue();
					BasicBlock* dest = switchCase.getCaseSuccessor();
					Expression* caseCondition = nullptr;
					if (dest == bb || defaultCondition != nullptr)
					{
						const auto& type = cast<IntegerExpressionType>(ctx.getType(*caseValue->getType()));
						Expression* numericConstant = ctx.numeric(type, caseValue->getLimitedValue());
						caseCondition = ctx.nary(NAryOperatorExpression::Equal, testVariable, numericConstant);
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
	auto sythesizedVariable = ctx.assignable(ctx.getIntegerType(false, 32), "dispatch");
	
	SmallDenseMap<PreAstBasicBlock*, NAryOperatorExpression*> caseConditions;
	for (auto edge : redirectedEdgeList)
	{
		auto iter = caseConditions.find(edge->to);
		if (iter == caseConditions.end())
		{
			Expression* numericConstant = ctx.numeric(ctx.getIntegerType(false, 32), caseConditions.size());
			auto condition = ctx.nary(NAryOperatorExpression::Equal, sythesizedVariable, numericConstant);
			iter = caseConditions.insert({edge->to, condition}).first;
			
			PreAstBasicBlockEdge& newEdge = createEdge(newBlock, *edge->to, *condition);
			newEdge.from->successors.push_back(&newEdge);
			newEdge.to->predecessors.push_back(&newEdge);
		}
		
		Statement* assignment = ctx.expr(ctx.nary(NAryOperatorExpression::Assign, sythesizedVariable, iter->second->getOperand(1)));
		edge->from->blockStatement = ctx.append(edge->from->blockStatement, assignment);
		edge->setTo(newBlock);
	}
	return newBlock;
}

void PreAstContext::view() const
{
	ViewGraph(const_cast<PreAstContext*>(this), "Pre-AST Basic Block Graph");
}
