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
#include <llvm/IR/Constants.h>
#include <llvm/ADT/DepthFirstIterator.h>
#include <llvm/ADT/PostOrderIterator.h>
#include <llvm/Analysis/DominanceFrontier.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/Instructions.h>
SILENCE_LLVM_WARNINGS_END()

#include <algorithm>
#include <deque>
#include <functional>
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
	
	// Basic graph slice algorithm. Passes every unique simple path to the `action` parameter.
	template<typename TAction>
	void buildGraphSlice(TAction&& action, AstGrapher& grapher, AstGraphNode* currentNode, const unordered_set<AstGraphNode*>& sinkNodes, LinkedNode<AstGraphNode>* parentLink = nullptr)
	{
		LinkedNode<AstGraphNode> childLink(currentNode, parentLink);
		
		if (sinkNodes.count(currentNode) == 1)
		{
			action(&childLink);
		}
		
		auto end = AstGraphTr::child_end(currentNode);
		for (auto iter = AstGraphTr::child_begin(currentNode); iter != end; ++iter)
		{
			bool found = false;
			AstGraphNode* explored = *iter;
			for (auto link = &childLink; link != nullptr; link = link->previous)
			{
				if (explored == link->element)
				{
					found = true;
					break;
				}
			}
			
			if (!found)
			{
				//buildGraphSlice(action, *iter, sinkNodes, &childLink);
			}
		}
	}
	
	// Enumerate reaching conditions for each basic block in a graph slice.
	class ReachingConditions
	{
		AstGrapher& grapher;
		
	public:
		typedef deque<const AstGraphNode*> Path;
		typedef unordered_multimap<Statement*, Path> PathMap;
		PathMap conditions;
		
	private:
		typedef vector<Path> PathCollection;
		
		void reachSlice(PathCollection::const_iterator begin, PathCollection::const_iterator end, Path& prefix)
		{
			if (begin == end)
			{
				return;
			}
			
			if (prefix.size() > 0)
			{
				auto back = prefix.back();
				if (back == nullptr)
				{
					return;
				}
				
				conditions.insert({back->node, prefix});
			}
			
			auto referenceIter = begin;
			const AstGraphNode* referenceNode = begin->at(prefix.size());
			for (auto iter = begin; iter != end; iter++)
			{
				const AstGraphNode* thisNode = iter->at(prefix.size());
				if (thisNode != referenceNode)
				{
					prefix.push_back(referenceNode);
					reachSlice(referenceIter, iter, prefix);
					prefix.pop_back();
					
					referenceIter = iter;
					referenceNode = thisNode;
				}
			}
			
			prefix.push_back(referenceNode);
			reachSlice(referenceIter, end, prefix);
			prefix.pop_back();
		}
		
	public:
		ReachingConditions(AstGrapher& grapher)
		: grapher(grapher)
		{
		}
		
		void build(AstGraphNode* regionStart, AstGraphNode* regionEnd)
		{
			PathCollection sinkNodePaths;
			buildGraphSlice([&](LinkedNode<AstGraphNode>* link)
			{
				Path result { nullptr };
				for (auto iter = link; iter != nullptr; iter = iter->previous)
				{
					result.push_front(iter->element);
				}
				sinkNodePaths.push_back(move(result));
			}, grapher, regionStart, { regionEnd });
			
			sort(sinkNodePaths.begin(), sinkNodePaths.end(), [&](const Path& a, const Path& b)
			{
				return lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
			});
			
			Path empty;
			reachSlice(sinkNodePaths.begin(), sinkNodePaths.end(), empty);
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
	
	Expression* buildReachingCondition(DumbAllocator<>& pool, AstGrapher& grapher, pair<ReachingConditions::PathMap::const_iterator, ReachingConditions::PathMap::const_iterator> range)
	{
		Expression* orAll = nullptr;
		for (auto iter = range.first; iter != range.second; iter++)
		{
			Expression* andAll = nullptr;
			BasicBlock* parentBlock = nullptr;
			for (const AstGraphNode* graphNode : iter->second)
			{
				if (parentBlock != nullptr)
				{
					auto terminator = parentBlock->getTerminator();
					if (auto br = dyn_cast<BranchInst>(terminator))
					{
						if (br->isConditional())
						{
							Expression* condition = pool.allocate<ValueExpression>(*br->getCondition());
							if (br->getSuccessor(1) == grapher.getBlockAtEntry(graphNode->node))
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
				parentBlock = grapher.getBlockAtExit(graphNode->node);
			}
			
			orAll = coalesce(pool, BinaryOperatorExpression::ShortCircuitOr, orAll, andAll);
		}
		return orAll;
	}
	
	DomTreeNode* walkUp(PostDominatorTree& tree, AstGrapher& grapher, DomTreeNode& node)
	{
		BasicBlock* predecessor = node.getBlock();
		if (AstGraphNode* astNode = grapher.getGraphNodeFromEntry(predecessor))
		{
			predecessor = astNode->exit;
		}
		return tree.getNode(predecessor)->getIDom();
	}
	
	void findBackEdgeDestinations(BasicBlock* entry, deque<BasicBlock*>& stack, unordered_set<BasicBlock*>& result)
	{
		stack.push_back(entry);
		for (BasicBlock* bb : successors(entry))
		{
			if (find(stack.rbegin(), stack.rend(), bb) == stack.rend())
			{
				findBackEdgeDestinations(bb, stack, result);
			}
			else
			{
				result.insert(bb);
			}
		}
		stack.pop_back();
	}
	
	unordered_set<BasicBlock*> findBackEdgeDestinations(BasicBlock& entryPoint)
	{
		unordered_set<BasicBlock*> result;
		deque<BasicBlock*> visitedStack;
		findBackEdgeDestinations(&entryPoint, visitedStack, result);
		return result;
	}
	
	void recursivelyAddBreakStatements(AstGrapher& grapher, AstGraphNode* node, BasicBlock* exitNode)
	{
		if (auto* sequence = dyn_cast<SequenceNode>(node->node))
		{
			// basic block exits loop scope?
			if (node->exit == exitNode)
			{
				bool success = sequence->append(BreakNode::breakNode);
				if (!success)
				{
					abort();
				}
			}
			
			for (size_t i = 0; i < sequence->count; i++)
			{
				if (AstGraphNode* childNode = grapher.getGraphNode(sequence->nodes[i]))
				{
					recursivelyAddBreakStatements(grapher, childNode, exitNode);
				}
			}
		}
	}
}

#pragma mark - AST Pass
char AstBackEnd::ID = 0;

void AstBackEnd::getAnalysisUsage(llvm::AnalysisUsage &au) const
{
	au.addRequired<DominatorTreeWrapperPass>();
	au.addRequired<PostDominatorTree>();
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
	
	// Identify loops, then visit basic blocks in post-order. If the basic block if the head
	// of a cyclic region, process the loop. Otherwise, if the basic block is the start of a single-entry-single-exit
	// region, process that region.
	
	PostDominatorTree& postDomTree = getAnalysis<PostDominatorTree>(fn);
	DominatorTree& domTree = getAnalysis<DominatorTreeWrapperPass>(fn).getDomTree();
	auto backNodes = findBackEdgeDestinations(fn.getEntryBlock());
	
	for (BasicBlock* entry : post_order(&fn.getEntryBlock()))
	{
		grapher->addBasicBlock(*entry);
		
		// Very naïve region detection algorithm based on the definition of regions:
		// - A dominates B
		// - B postdominates A
		// - Loops that include A also include B (guaranteed by processing loops first)
		DomTreeNode* domNode = postDomTree.getNode(entry);
		while (DomTreeNode* successor = walkUp(postDomTree, *grapher, *domNode))
		{
			if (BasicBlock* exit = successor->getBlock())
			{
				domNode = successor;
				
				bool entryDomsExit = domTree.dominates(entry, exit);
				bool exitPostDomsEntry = postDomTree.dominates(exit, entry);
				if (entryDomsExit && exitPostDomsEntry)
				{
					// Because of the Single-Entry Single-Exit Loop pass that has to run before this one, any loop is
					// necessarily a single-entry single-exit region.
					if (backNodes.count(entry) == 0)
					{
						changed |= runOnRegion(fn, *entry, *exit);
					}
					else
					{
						changed |= runOnLoop(fn, *entry, *exit);
					}
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
	
	return changed;
}

bool AstBackEnd::runOnLoop(Function& fn, BasicBlock& entry, BasicBlock& exit)
{
	// The SESELoop pass already did the meaningful transformations on the loop region:
	// it's now a single-entry, single-exit region, loop membership has already been refined, etc.
	// We really just have to emit the AST.
	// Basically, we want a "while True" loop with break statements wherever we exit the loop scope.
	
	bool changed = runOnRegion(fn, entry, exit);
	AstGraphNode* node = grapher->getGraphNodeFromEntry(&entry);
	recursivelyAddBreakStatements(*grapher, node, &exit);
	return changed;
}

bool AstBackEnd::runOnRegion(Function& fn, BasicBlock& entry, BasicBlock& exit)
{
	AstGraphNode* astEntry = grapher->getGraphNodeFromEntry(&entry);
	AstGraphNode* astExit = grapher->getGraphNodeFromEntry(&exit);
	
	// Build reaching conditions.
	ReachingConditions reach(*grapher);
	reach.build(astEntry, astExit);
	
	// Structure nodes into `if` statements using reaching conditions. Traverse nodes in topological order (reverse
	// postorder). We can't use LLVM's ReversePostOrderTraversal class here because we're working with a subgraph.
	vector<Statement*> listOfNodes;
	for (Statement* node : reversePostOrder(astEntry, astExit))
	{
		auto pair = reach.conditions.equal_range(node);
		
		Expression* condition = buildReachingCondition(pool, *grapher, pair);
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
	Statement* asSequence = pool.allocate<SequenceNode>(nodeArray, count, count);
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
