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
#include <llvm/Analysis/RegionInfo.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <algorithm>
#include <deque>
#include <functional>
#include <iostream>
#include <unordered_set>
#include <vector>

using namespace llvm;
using namespace std;

extern void print(raw_ostream& os, const SmallVector<Expression*, 4>& expressionList, const char* elemSep)
{
	os << '(';
	for (auto iter = expressionList.begin(); iter != expressionList.end(); iter++)
	{
		if (iter != expressionList.begin())
		{
			os << ' ' << elemSep << ' ';
		}
		(*iter)->print(os);
	}
	os << ')';
}

extern void dump(const SmallVector<Expression*, 4>& expressionList, const char* elemSep)
{
	raw_os_ostream rerr(cerr);
	print(rerr, expressionList, elemSep);
	rerr << '\n';
}

extern void dump(const SmallVector<SmallVector<Expression*, 4>, 4>& expressionList, const char* rowSep, const char* elemSep)
{
	raw_os_ostream rerr(cerr);
	for (auto iter = expressionList.begin(); iter != expressionList.end(); iter++)
	{
		if (iter != expressionList.begin())
		{
			rerr << ' ' << rowSep << ' ';
		}
		print(rerr, *iter, elemSep);
	}
	rerr << '\n';
}

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
	
	struct GraphSlice
	{
		DumbAllocator<>& pool;
		AstGrapher& grapher;
		
		GraphSlice(DumbAllocator<>& pool, AstGrapher& grapher)
		: pool(pool), grapher(grapher)
		{
		}
		
		template<typename TAction>
		void build(TAction&& action, AstGraphNode* currentNode, AstGraphNode* sinkNode, LinkedNode<AstGraphNode>* parentLink = nullptr)
		{
			for (auto iter = parentLink; iter != nullptr; iter = iter->previous)
			{
				// Ignore back edges.
				if (iter->element == currentNode)
				{
					return;
				}
			}
			
			auto childLink = pool.allocate<LinkedNode<AstGraphNode>>(currentNode, parentLink);
			action(childLink);
			
			if (currentNode != sinkNode)
			{
				auto end = AstGraphTr::child_end(currentNode);
				for (auto iter = AstGraphTr::child_begin(currentNode); iter != end; ++iter)
				{
					build(action, *iter, sinkNode, childLink);
				}
			}
		}
	};
	
	class ReachingConditions
	{
		GraphSlice slice;
		
	public:
		unordered_map<Statement*, vector<LinkedNode<AstGraphNode>*>> conditions;
		
		ReachingConditions(DumbAllocator<>& pool, AstGrapher& grapher)
		: slice(pool, grapher)
		{
		}
		
		void build(AstGraphNode* regionStart, AstGraphNode* regionEnd)
		{
			slice.build([&](LinkedNode<AstGraphNode>* link)
			{
				conditions[link->element->node].push_back(link);
			}, regionStart, regionEnd);
		}
	};
	
	void postOrder(vector<Statement*>& into, unordered_set<Statement*>& visited, AstGraphNode* current, AstGraphNode* exit)
	{
		if (visited.count(current->node) == 0)
		{
			visited.insert(current->node);
			if (current != exit)
			{
				auto begin = AstGraphTr::child_begin(current);
				auto end = AstGraphTr::child_end(current);
				for (auto iter = begin; iter != end; ++iter)
				{
					postOrder(into, visited, *iter, exit);
				}
			}
			into.push_back(current->node);
		}
	}
	
	vector<Statement*> reversePostOrder(AstGraphNode* entry, AstGraphNode* exit)
	{
		vector<Statement*> result;
		unordered_set<Statement*> visited;
		postOrder(result, visited, entry, exit);
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
	
	void expandToProductOfSums(
		SmallVector<Expression*, 4>& stack,
		SmallVector<SmallVector<Expression*, 4>, 4>& output,
		SmallVector<SmallVector<Expression*, 4>, 4>::const_iterator sumOfProductsIter,
		SmallVector<SmallVector<Expression*, 4>, 4>::const_iterator sumOfProductsEnd)
	{
		if (sumOfProductsIter == sumOfProductsEnd)
		{
			output.push_back(stack);
		}
		else
		{
			auto nextRow = sumOfProductsIter + 1;
			for (Expression* expr : *sumOfProductsIter)
			{
				stack.push_back(expr);
				expandToProductOfSums(stack, output, nextRow, sumOfProductsEnd);
				stack.pop_back();
			}
		}
	}
	
	Expression* simplifySumOfProducts(DumbAllocator<>& pool, SmallVector<SmallVector<Expression*, 4>, 4>& sumOfProducts)
	{
		if (sumOfProducts.size() == 0)
		{
			return TokenExpression::trueExpression;
		}
		
		SmallVector<SmallVector<Expression*, 4>, 4> productOfSums;
		
		// This is a NP-complete problem, so we'll have to cut corners a little bit to make things acceptable.
		// The `expr` vector is in disjunctive normal form: each inner vector ANDs ("multiplies") all of its operands,
		// and each vector is ORed ("added"). In other words, we have a sum of products.
		// By the end, we want a product of sums, since this simplifies expression matching to nest if statements.
		// In this specific instance of the problem, we know that common terms will arise often (because of deeply
		// nested conditions), but contradictions probably never will.
		
		// Step 1: collect identical terms.
		if (sumOfProducts.size() > 1)
		{
			auto otherProductsBegin = sumOfProducts.begin();
			auto& firstProduct = *otherProductsBegin;
			otherProductsBegin++;
			
			auto termIter = firstProduct.begin();
			while (termIter != firstProduct.end())
			{
				SmallVector<SmallVector<Expression*, 4>::iterator, 4> termLocations;
				for (auto iter = otherProductsBegin; iter != sumOfProducts.end(); iter++)
				{
					auto termLocation = find_if(iter->begin(), iter->end(), [&](Expression* that)
					{
						return that->isReferenceEqual(*termIter);
					});
					
					if (termLocation == iter->end())
					{
						break;
					}
					termLocations.push_back(termLocation);
				}
				
				if (termLocations.size() == sumOfProducts.size() - 1)
				{
					// The term exists in every product. Isolate it.
					productOfSums.emplace_back();
					productOfSums.back().push_back(*termIter);
					size_t i = 0;
					for (auto iter = otherProductsBegin; iter != sumOfProducts.end(); iter++)
					{
						iter->erase(termLocations[i]);
						i++;
					}
					termIter = firstProduct.erase(termIter);
				}
				else
				{
					termIter++;
				}
			}
			
			// Erase empty products.
			auto possiblyEmptyIter = sumOfProducts.begin();
			while (possiblyEmptyIter != sumOfProducts.end())
			{
				if (possiblyEmptyIter->size() == 0)
				{
					possiblyEmptyIter = sumOfProducts.erase(possiblyEmptyIter);
				}
				else
				{
					possiblyEmptyIter++;
				}
			}
		}
		
		// Step 2: transform remaining items in sumOfProducts into a product of sums.
		auto& firstProduct = sumOfProducts.front();
		decltype(productOfSums)::value_type stack;
		for (Expression* expr : firstProduct)
		{
			stack.push_back(expr);
			expandToProductOfSums(stack, productOfSums, sumOfProducts.begin() + 1, sumOfProducts.end());
			stack.pop_back();
		}
		
		// Step 3: visit each sum and delete A | ~A situations.
		auto sumIter = productOfSums.begin();
		while (sumIter != productOfSums.end())
		{
			auto& sum = *sumIter;
			auto iter = sum.begin();
			auto end = sum.end();
			while (iter != end)
			{
				Expression* e = *iter;
				auto negation = end;
				if (auto negated = dyn_cast<UnaryOperatorExpression>(e))
				{
					assert(negated->type == UnaryOperatorExpression::LogicalNegate);
					e = negated->operand;
					negation = find_if(iter + 1, end, [&](Expression* that)
					{
						return that->isReferenceEqual(e);
					});
				}
				else
				{
					negation = find_if(iter + 1, end, [&](Expression* that)
					{
						if (auto negated = dyn_cast<UnaryOperatorExpression>(that))
						{
							assert(negated->type == UnaryOperatorExpression::LogicalNegate);
							return negated->operand->isReferenceEqual(e);
						}
						return false;
					});
				}
				
				if (negation != end)
				{
					end = remove(negation, end, *negation);
					end = remove(iter, end, *iter);
				}
				else
				{
					iter++;
				}
			}
			
			sum.erase(end, sum.end());
			
			// Delete empty sums.
			if (sum.size() == 0)
			{
				sumIter = productOfSums.erase(sumIter);
			}
			else
			{
				sumIter++;
			}
		}
		
		// Final step: produce expression
		if (sumOfProducts.size() == 0)
		{
			return TokenExpression::trueExpression;
		}
		
		Expression* andAll = nullptr;
		for (const auto& sum : productOfSums)
		{
			Expression* orAll = nullptr;
			for (Expression * expression : sum)
			{
				orAll = coalesce(pool, BinaryOperatorExpression::ShortCircuitOr, orAll, expression);
			}
			andAll = coalesce(pool, BinaryOperatorExpression::ShortCircuitAnd, andAll, orAll);
		}
		
		return andAll;
	}
	
	Expression* buildReachingCondition(DumbAllocator<>& pool, AstGrapher& grapher, const vector<LinkedNode<AstGraphNode>*>& links)
	{
		SmallVector<SmallVector<Expression*, 4>, 4> sumOfProducts;
		for (const auto* link : links)
		{
			sumOfProducts.emplace_back();
			while (link != nullptr)
			{
				auto thisBlock = grapher.getBlockAtEntry(link->element->node);
				if (auto parent = link->previous)
				{
					auto terminator = grapher.getBlockAtExit(parent->element->node)->getTerminator();
					if (auto br = dyn_cast<BranchInst>(terminator))
					{
						if (br->isConditional())
						{
							Expression* condition = pool.allocate<ValueExpression>(*br->getCondition());
							if (br->getSuccessor(1) == thisBlock)
							{
								condition = pool.allocate<UnaryOperatorExpression>(UnaryOperatorExpression::LogicalNegate, condition);
							}
							sumOfProducts.back().push_back(condition);
						}
					}
					else
					{
						llvm_unreachable("implement other terminator instructions");
					}
				}
				link = link->previous;
			}
		}
		
		return simplifySumOfProducts(pool, sumOfProducts);
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
				if (!isa<ReturnInst>(exitNode->getTerminator()))
				{
					bool success = sequence->append(BreakNode::breakNode);
					if (!success)
					{
						abort();
					}
				}
			}
			
			for (size_t i = 0; i < sequence->count; i++)
			{
				if (auto subSequence = dyn_cast<SequenceNode>(sequence->nodes[i]))
				{
					if (AstGraphNode* childNode = grapher.getGraphNode(subSequence))
					{
						recursivelyAddBreakStatements(grapher, childNode, exitNode);
					}
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
	au.addRequired<DominanceFrontier>();
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
	
	// Identify loops, then visit basic blocks in post-order. If the basic block if the head
	// of a cyclic region, process the loop. Otherwise, if the basic block is the start of a single-entry-single-exit
	// region, process that region.
	
	domTree = &getAnalysis<DominatorTreeWrapperPass>(fn).getDomTree();
	postDomTree = &getAnalysis<PostDominatorTree>(fn);
	frontier = &getAnalysis<DominanceFrontier>(fn);
	
	auto backNodes = findBackEdgeDestinations(fn.getEntryBlock());
	
	for (BasicBlock* entry : post_order(&fn.getEntryBlock()))
	{
		grapher->addBasicBlock(*entry);
		
		DomTreeNode* domNode = postDomTree->getNode(entry);
		while (DomTreeNode* successor = walkUp(*postDomTree, *grapher, *domNode))
		{
			if (BasicBlock* exit = successor->getBlock())
			{
				domNode = successor;
				
				if (isRegion(*entry, *exit))
				{
					if (backNodes.count(entry) == 0)
					{
						changed |= runOnRegion(fn, *entry, *exit);
					}
					else
					{
						changed |= runOnLoop(fn, *entry, *exit);
					}
				}
				else if (!domTree->dominates(entry, exit))
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
	
	// with lldb and libc++:
	// p grapher.__ptr_.__first_->getGraphNodeFromEntry(&fn.getEntryBlock())->node->dump()
	return changed;
}

bool AstBackEnd::runOnLoop(Function& fn, BasicBlock& entry, BasicBlock& exit)
{
	// The SESELoop pass already did the meaningful transformations on the loop region:
	// it's now a single-entry, single-exit region, loop membership has already been refined, etc.
	// We really just have to emit the AST.
	// Basically, we want a "while true" loop with break statements wherever we exit the loop scope.
	
	bool changed = runOnRegion(fn, entry, exit);
	AstGraphNode* node = grapher->getGraphNodeFromEntry(&entry);
	recursivelyAddBreakStatements(*grapher, node, &exit);
	
	Statement* endlessLoop = pool.allocate<LoopNode>(node->node);
	grapher->updateRegion(entry, exit, *endlessLoop);
	return changed;
}

bool AstBackEnd::runOnRegion(Function& fn, BasicBlock& entry, BasicBlock& exit)
{
	AstGraphNode* astEntry = grapher->getGraphNodeFromEntry(&entry);
	AstGraphNode* astExit = grapher->getGraphNodeFromEntry(&exit);
	
	// Build reaching conditions.
	ReachingConditions reach(pool, *grapher);
	reach.build(astEntry, astExit);
	
	// Structure nodes into `if` statements using reaching conditions. Traverse nodes in topological order (reverse
	// postorder). We can't use LLVM's ReversePostOrderTraversal class here because we're working with a subgraph.
	vector<Statement*> listOfNodes;
	for (Statement* node : reversePostOrder(astEntry, astExit))
	{
		auto& path = reach.conditions.at(node);
		Expression* condition = buildReachingCondition(pool, *grapher, path);
		
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

bool AstBackEnd::isRegion(BasicBlock &entry, BasicBlock &exit)
{
	// Exclude so-called trivial regions.
	unsigned successorsCount = entry.getTerminator()->getNumSuccessors();
	if (successorsCount <= 1 && &exit == *succ_begin(&entry))
	{
		return false;
	}
	
	auto entrySuccessors = frontier->find(&entry)->second;
	
	// This apparently happens for loops. I don't understand it as well as I should...
	if (!domTree->dominates(&entry, &exit))
	{
		for (auto iter = entrySuccessors.begin(); iter != entrySuccessors.end(); ++iter)
		{
			if (*iter != &entry && *iter != &exit)
			{
				return false;
			}
		}
		return true;
	}
	
	auto exitSuccessors = frontier->find(&exit)->second;
	
	// Edges pointing out aren't allowed (except from the exit)
	for (auto iter = entrySuccessors.begin(); iter != entrySuccessors.end(); iter++)
	{
		if (*iter == &entry || *iter == &exit)
		{
			continue;
		}
		
		if (exitSuccessors.find(*iter) == exitSuccessors.end())
		{
			return false;
		}
		
		for (BasicBlock* child : successors(*iter))
		{
			if (domTree->dominates(&entry, child) && !domTree->dominates(&exit, child))
			{
				return false;
			}
		}
	}
	
	// Edges pointing back in are not allowed
	for (auto iter = exitSuccessors.begin(); iter != exitSuccessors.end(); iter++)
	{
		if (domTree->properlyDominates(&entry, *iter) && *iter != &exit)
		{
			return false;
		}
	}
	
	return true;
}

INITIALIZE_PASS_BEGIN(AstBackEnd, "astbe", "AST Back-End", true, false)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(PostDominatorTree)
INITIALIZE_PASS_END(AstBackEnd, "astbe", "AST Back-End", true, false)

AstBackEnd* createAstBackEnd()
{
	return new AstBackEnd;
}
