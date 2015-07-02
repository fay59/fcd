//
//  program_output.cpp
//  x86Emulator
//
//  Created by Félix on 2015-06-16.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#include "passes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/PostOrderiterator.h>
#include <llvm/Analysis/DominanceFrontier.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <iostream>
#include <string>
#include <unordered_set>
#include <vector>

using namespace llvm;
using namespace std;

namespace
{
	DomTreeNode* walkUp(PostDominatorTree& tree, std::unordered_map<BasicBlock*, BasicBlock*>& shortcuts, DomTreeNode& node)
	{
		auto iter = shortcuts.find(node.getBlock());
		auto nodeToCheck = iter == shortcuts.end() ? &node : tree.getNode(iter->second);
		return nodeToCheck->getIDom();
	}
	
	inline string indent(unsigned times)
	{
		return string('\t', times);
	}
	
	constexpr char nl = '\n';
	
	typedef GraphTraits<Inverse<BasicBlock*>> InvBlockTraits;
}

#pragma mark - AST Nodes
void AstNode::dump() const
{
	raw_os_ostream rerr(cerr);
	print(rerr);
}

void ValueNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent);
	value->print(os);
	os << nl;
}

void SequenceNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	if (indent > 0)
	{
		os << ::indent(indent - 1);
	}
	os << '{' << nl;
	
	for (size_t i = 0; i < count; i++)
	{
		nodes[i]->print(os, indent + indent == 0);
	}
	
	if (indent > 0)
	{
		os << ::indent(indent - 1);
	}
	os << '}' << nl;
}

void IfElseNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent) << "if ";
	condition->print(os, 0);
	ifBody->print(os, indent);
	if (elseBody != nullptr)
	{
		os << ::indent(indent) << "else" << nl;
		elseBody->print(os, indent);
	}
}

void GotoNode::print(llvm::raw_ostream &os, unsigned int indent) const
{
	os << ::indent(indent) << "goto ";
	target->printAsOperand(os);
	os << nl;
}

#pragma mark - AST Pass
char AstBackEnd::ID = 0;

void AstBackEnd::getAnalysisUsage(llvm::AnalysisUsage &au) const
{
	au.addRequired<DominatorTreeWrapperPass>();
	au.addRequired<LoopInfoWrapperPass>();
	au.addRequired<RegionInfoPass>();
	au.addRequired<PostDominatorTree>();
	au.addRequired<DominanceFrontier>();
	au.setPreservesAll();
}

bool AstBackEnd::runOnModule(llvm::Module &m)
{
	bool changed = false;
	astPerFunction.clear();
	for (Function& fn : m)
	{
		changed |= runOnFunction(fn);
	}
	return changed;
}

bool AstBackEnd::runOnFunction(llvm::Function& fn)
{
	// sanity checks
	auto iter = astPerFunction.find(&fn);
	if (iter != astPerFunction.end())
	{
		return false;
	}
	
	if (fn.empty())
	{
		return false;
	}
	
	bool changed = false;
	astPerBlock.clear();
	postDomTraversalShortcuts.clear();
	
	// Identify loops, then visit basic blocks in post-order. If the basic block if the head
	// of a cyclic region, process the loop. Otherwise, if the basic block is the start of a single-entry-single-exit
	// region, process that region.
	
	LoopInfo& loopInfo = getAnalysis<LoopInfoWrapperPass>(fn).getLoopInfo();
	PostDominatorTree& postDomTree = getAnalysis<PostDominatorTree>(fn);
	domFrontier = &getAnalysis<DominanceFrontier>(fn);
	domTree = &getAnalysis<DominatorTreeWrapperPass>(fn).getDomTree();
	
	for (BasicBlock* entry : post_order(&fn.getEntryBlock()))
	{
		(void) toAstNode(*entry);
		
		if (loopInfo.isLoopHeader(entry))
		{
			changed |= runOnLoop(*loopInfo.getLoopFor(entry));
		}
		else
		{
			// Algorithm for region detection borrowed from LLVM's RegionInfoImpl.h file.
			// RegionInfo would be inconvenient here because we couldn't iterate over loops and regions at the same time
			BasicBlock* lastExit = entry;
			DomTreeNode* domNode = postDomTree.getNode(entry);
			while (DomTreeNode* successor = walkUp(postDomTree, postDomTraversalShortcuts, *domNode))
			{
				if (BasicBlock* exit = successor->getBlock())
				{
					domNode = successor;
					if (isRegion(entry, exit))
					{
						lastExit = exit;
						changed |= runOnRegion(*entry, *exit);
					}
					else if (!postDomTree.dominates(entry, exit))
					{
						break;
					}
				}
				else
				{
					break;
				}
			}
			
			if (lastExit != entry)
			{
				auto iter = postDomTraversalShortcuts.find(lastExit);
				postDomTraversalShortcuts[entry] = iter == postDomTraversalShortcuts.end()
					? lastExit
					: iter->second;
			}
		}
	}
	
	return changed;
}

bool AstBackEnd::isRegion(BasicBlock* entry, BasicBlock* exit)
{
	auto& entrySuccessors = domFrontier->find(entry)->second;
	auto& exitSuccessors = domFrontier->find(exit)->second;
	
	if (!domTree->dominates(entry, exit))
	{
		for (auto iter = entrySuccessors.begin(); iter != entrySuccessors.end(); iter++)
		{
			if (*iter != entry && *iter != exit)
			{
				return false;
			}
		}
	}
	
	for (auto iter = entrySuccessors.begin(); iter != entrySuccessors.end(); iter++)
	{
		if (*iter == entry || *iter == exit)
		{
			continue;
		}
		
		if (exitSuccessors.find(*iter) == exitSuccessors.end())
		{
			return false;
		}
		
		for (auto blockIter = InvBlockTraits::child_begin(*iter); blockIter != InvBlockTraits::child_end(*iter); blockIter++)
		{
			if (domTree->dominates(entry, *blockIter) && !domTree->dominates(exit, *blockIter))
			{
				return false;
			}
		}
	}
	
	for (auto iter = exitSuccessors.begin(); iter != exitSuccessors.end(); iter++)
	{
		if (domTree->properlyDominates(entry, *iter) && *iter != exit)
		{
			return false;
		}
	}
	
	return true;
}

bool AstBackEnd::runOnLoop(Loop& loop)
{
	return false;
}

bool AstBackEnd::runOnRegion(BasicBlock& entry, BasicBlock& exit)
{
	return false;
}

AstNode* AstBackEnd::toAstNode(BasicBlock& bb)
{
	size_t childCount = bb.size();
	AstNode** nodeArray = astAllocator.allocateDynamic<AstNode*>(childCount);
	AstNode** entryPointer = nodeArray;
	for (Instruction& inst : bb)
	{
		if (auto br = dyn_cast<BranchInst>(&inst))
		{
			AstNode* ifDest = astAllocator.allocate<GotoNode>(*br->getSuccessor(0));
			if (br->isConditional())
			{
				// Just be careful: it won't be possible to use pointer equality to compare the condition AST node.
				AstNode* condition = astAllocator.allocate<ValueNode>(*br->getCondition());
				AstNode* elseDest = astAllocator.allocate<GotoNode>(*br->getSuccessor(1));
				*entryPointer = astAllocator.allocate<IfElseNode>(condition, ifDest, elseDest);
			}
			else
			{
				*entryPointer = ifDest;
			}
		}
		else
		{
			assert((!isa<TerminatorInst>(inst) || isa<ReturnInst>(inst)) && "implement support for other terminators!");
			*entryPointer = astAllocator.allocate<ValueNode>(inst);
		}
		entryPointer++;
	}
	
	auto& mapEntry = astPerBlock[&bb];
	mapEntry = astAllocator.allocate<SequenceNode>(nodeArray, childCount);
	return mapEntry;
}

INITIALIZE_PASS_BEGIN(AstBackEnd, "astbe", "AST Back-End", true, false)
INITIALIZE_PASS_DEPENDENCY(LoopInfoWrapperPass)
INITIALIZE_PASS_DEPENDENCY(RegionInfoPass)
INITIALIZE_PASS_DEPENDENCY(PostDominatorTree)
INITIALIZE_PASS_END(AstBackEnd, "astbe", "AST Back-End", true, false)

AstBackEnd* createAstBackEnd()
{
	return new AstBackEnd;
}
