//
//  program_output.cpp
//  x86Emulator
//
//  Created by Félix on 2015-06-16.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#include "ast_grapher.h"
#include "passes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/DepthFirstIterator.h>
#include <llvm/ADT/PostOrderIterator.h>
#include <llvm/Analysis/DominanceFrontier.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/Instructions.h>
SILENCE_LLVM_WARNINGS_END()

#include <iostream>
#include <unordered_set>
#include <vector>

using namespace llvm;
using namespace std;

namespace
{
	typedef GraphTraits<AstGraphNode> AstGraphTr;
	
	template<typename TElem>
	struct LinkedNode
	{
		typedef LinkedNode<TElem> Node;
		Node* previous;
		TElem* element;
		
		LinkedNode(TElem* element, Node* previous = nullptr)
		: previous(previous), element(element)
		{
		}
	};
	
	// For each AST node, compute the list of previous AST nodes that must be traversed to reach it. This is basically
	// turning the acyclic directed graph of AST nodes that we have into a depth-first tree.
	// (At this point, graph regions with cycles have been collapsed into a single AST loop node. There is therefore no
	// cycle in the graph that we have.)
	struct ReachingConditions
	{
		DumbAllocator<>& pool;
		AstGrapher& grapher;
		unordered_map<Statement*, vector<LinkedNode<Statement>*>> conditions;
		
		ReachingConditions(DumbAllocator<>& pool, AstGrapher& grapher)
		: pool(pool), grapher(grapher)
		{
		}
		
		void recursivelyBuild(AstGraphNode* currentNode, AstGraphNode* regionEnd, LinkedNode<Statement>* parentLink = nullptr)
		{
			auto childLink = pool.allocate<LinkedNode<Statement>>(currentNode->node, parentLink);
			conditions[currentNode->node].push_back(childLink);
			
			if (currentNode != regionEnd)
			{
				auto end = AstGraphTr::child_end(currentNode);
				for (auto iter = AstGraphTr::child_begin(currentNode); iter != end; ++iter)
				{
					recursivelyBuild(*iter, regionEnd, childLink);
				}
			}
		}
		
		void build(BasicBlock& regionStart, BasicBlock& regionEnd)
		{
			recursivelyBuild(grapher.getGraphNode(&regionStart), grapher.getGraphNode(&regionEnd));
		}
	};
	
	void postOrder(vector<Statement*>& into, AstGraphNode* current, AstGraphNode* exit)
	{
		if (current != exit)
		{
			auto begin = AstGraphTr::child_begin(current);
			auto end = AstGraphTr::child_end(current);
			for (auto iter = begin; iter != end; ++iter)
			{
				postOrder(into, *iter, exit);
			}
		}
		
		if (find(into.begin(), into.end(), current->node) == into.end())
		{
			into.push_back(current->node);
		}
	}
	
	vector<Statement*> reversePostOrder(AstGraphNode* entry, AstGraphNode* exit)
	{
		vector<Statement*> result;
		postOrder(result, entry, exit);
		reverse(result.begin(), result.end());
		return result;
	}
	
	inline Expression* coalesce(DumbAllocator<>& pool, BinaryOperatorExpression::BinaryOperatorType type, Expression* left, Expression* right)
	{
		if (left == nullptr)
		{
			return right;
		}
		
		if (right == nullptr)
		{
			return left;
		}
		
		return pool.allocate<BinaryOperatorExpression>(type, left, right);
	}
	
	Expression* buildReachingCondition(DumbAllocator<>& pool, AstGrapher& grapher, const vector<LinkedNode<Statement>*>& links)
	{
		Expression* orAll = nullptr;
		for (const auto* link : links)
		{
			Expression* andAll = nullptr;
			while (link != nullptr)
			{
				auto thisBlock = grapher.getBlockAtEntry(link->element);
				if (auto parent = link->previous)
				{
					auto terminator = grapher.getBlockAtExit(parent->element)->getTerminator();
					if (auto br = dyn_cast<BranchInst>(terminator))
					{
						if (br->isConditional())
						{
							Expression* condition = pool.allocate<ValueExpression>(*br->getCondition());
							if (br->getSuccessor(1) == thisBlock)
							{
								condition = pool.allocate<UnaryOperatorExpression>(UnaryOperatorExpression::LogicalNegate, condition);
							}
							andAll = coalesce(pool, BinaryOperatorExpression::ShortCircuitAnd, andAll, condition);
						}
					}
					else
					{
						llvm_unreachable("implement other terminator instructions");
					}
				}
				link = link->previous;
			}
			
			orAll = coalesce(pool, BinaryOperatorExpression::ShortCircuitOr, orAll, andAll);
		}
		return orAll;
	}
	
	DomTreeNode* walkUp(PostDominatorTree& tree, std::unordered_map<BasicBlock*, BasicBlock*>& shortcuts, DomTreeNode& node)
	{
		auto iter = shortcuts.find(node.getBlock());
		auto nodeToCheck = iter == shortcuts.end() ? &node : tree.getNode(iter->second);
		return nodeToCheck->getIDom();
	}
}

#pragma mark - AST Pass
char AstBackEnd::ID = 0;

void AstBackEnd::getAnalysisUsage(llvm::AnalysisUsage &au) const
{
	au.addRequired<DominatorTreeWrapperPass>();
	au.addRequired<LoopInfoWrapperPass>();
	au.addRequired<PostDominatorTree>();
	au.setPreservesAll();
}

bool AstBackEnd::runOnModule(llvm::Module &m)
{
	pool.clear();
	astPerFunction.clear();
	grapher.reset(new AstGrapher(pool));
	
	bool changed = false;
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
	postDomTraversalShortcuts.clear();
	
	// Identify loops, then visit basic blocks in post-order. If the basic block if the head
	// of a cyclic region, process the loop. Otherwise, if the basic block is the start of a single-entry-single-exit
	// region, process that region.
	
	LoopInfo& loopInfo = getAnalysis<LoopInfoWrapperPass>(fn).getLoopInfo();
	PostDominatorTree& postDomTree = getAnalysis<PostDominatorTree>(fn);
	DominatorTree& domTree = getAnalysis<DominatorTreeWrapperPass>(fn).getDomTree();
	
	for (BasicBlock* entry : post_order(&fn.getEntryBlock()))
	{
		grapher->addBasicBlock(*entry);
		
		if (loopInfo.isLoopHeader(entry))
		{
			changed |= runOnLoop(*loopInfo.getLoopFor(entry));
		}
		else
		{
			// Very naïve region detection algorithm based on the definition of regions:
			// - A dominates B
			// - B postdominates A
			// - Loops that include A also include B
			DomTreeNode* domNode = postDomTree.getNode(entry);
			while (DomTreeNode* successor = walkUp(postDomTree, postDomTraversalShortcuts, *domNode))
			{
				if (BasicBlock* exit = successor->getBlock())
				{
					domNode = successor;
					
					bool entryDomsExit = domTree.dominates(entry, exit);
					bool exitPostDomsEntry = postDomTree.dominates(exit, entry);
					bool sameLoop = loopInfo.getLoopFor(entry) == loopInfo.getLoopFor(exit);
					if (entryDomsExit && exitPostDomsEntry && sameLoop)
					{
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
		}
	}
	
	return changed;
}

bool AstBackEnd::runOnLoop(Loop& loop)
{
	return false;
}

bool AstBackEnd::runOnRegion(BasicBlock& entry, BasicBlock& exit)
{
	// Build reaching conditions.
	ReachingConditions reach(pool, *grapher);
	reach.build(entry, exit);
	
	// Structure nodes into `if` statements using reaching conditions. Traverse nodes in topological order (reverse
	// postorder). We can't use LLVM's ReversePostOrderTraversal class here because we're working with a subgraph.
	vector<Statement*> listOfNodes;
	AstGraphNode* astEntry = grapher->getGraphNode(&entry);
	AstGraphNode* astExit = grapher->getGraphNode(&exit);
	for (Statement* node : reversePostOrder(astEntry, astExit))
	{
		auto iter = reach.conditions.find(node);
		assert(iter != reach.conditions.end());
		
		Expression* condition = buildReachingCondition(pool, *grapher, iter->second);
		if (condition == nullptr)
		{
			listOfNodes.push_back(node);
		}
		else
		{
			Statement* ifNode = pool.allocate<IfElseNode>(condition, node);
			listOfNodes.push_back(ifNode);
		}
	}
	
	// Replace region withing AST grapher.
	size_t count = listOfNodes.size();
	Statement** nodeArray = pool.allocateDynamic<Statement*>(listOfNodes.size());
	copy(listOfNodes.begin(), listOfNodes.end(), nodeArray);
	Statement* asSequence = pool.allocate<SequenceNode>(nodeArray, count);
	grapher->updateRegion(entry, exit, *asSequence);
	
	return false;
}

INITIALIZE_PASS_BEGIN(AstBackEnd, "astbe", "AST Back-End", true, false)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(LoopInfoWrapperPass)
INITIALIZE_PASS_DEPENDENCY(PostDominatorTree)
INITIALIZE_PASS_END(AstBackEnd, "astbe", "AST Back-End", true, false)

AstBackEnd* createAstBackEnd()
{
	return new AstBackEnd;
}
