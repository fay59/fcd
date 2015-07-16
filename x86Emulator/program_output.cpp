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
		DumbAllocator& pool;
		AstGrapher& grapher;
		
		GraphSlice(DumbAllocator& pool, AstGrapher& grapher)
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
		
		ReachingConditions(DumbAllocator& pool, AstGrapher& grapher)
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
	
	inline Expression* logicalNegate(DumbAllocator& pool, Expression* toNegate)
	{
		if (auto unary = dyn_cast<UnaryOperatorExpression>(toNegate))
		{
			if (unary->type == UnaryOperatorExpression::LogicalNegate)
			{
				return unary->operand;
			}
		}
		return pool.allocate<UnaryOperatorExpression>(UnaryOperatorExpression::LogicalNegate, toNegate);
	}
	
	inline Expression* coalesce(DumbAllocator& pool, BinaryOperatorExpression::BinaryOperatorType type, Expression* left, Expression* right)
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
	
	inline Expression* collapse(DumbAllocator& pool, const SmallVector<Expression*, 4>& terms, BinaryOperatorExpression::BinaryOperatorType joint)
	{
		Expression* result = nullptr;
		for (auto expression : terms)
		{
			result = coalesce(pool, joint, result, expression);
		}
		return result;
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
	
	SmallVector<SmallVector<Expression*, 4>, 4> simplifySumOfProducts(DumbAllocator& pool, SmallVector<SmallVector<Expression*, 4>, 4>& sumOfProducts)
	{
		if (sumOfProducts.size() == 0)
		{
			// return empty vector
			return sumOfProducts;
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
		
		return productOfSums;
	}
	
	SmallVector<SmallVector<Expression*, 4>, 4> buildReachingCondition(DumbAllocator& pool, AstGrapher& grapher, const vector<LinkedNode<AstGraphNode>*>& links)
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
								condition = logicalNegate(pool, condition);
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
			reverse(sumOfProducts.back().begin(), sumOfProducts.back().end());
		}
		
		return simplifySumOfProducts(pool, sumOfProducts);
	}
	
	DomTreeNode* walkUp(PostDominatorTree& tree, const unordered_map<BasicBlock*, BasicBlock*>& shortcuts, DomTreeNode& node)
	{
		BasicBlock* predecessor = node.getBlock();
		
		auto iter = shortcuts.find(predecessor);
		if (iter != shortcuts.end())
		{
			predecessor = iter->second;
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
	
	void recursivelyAddBreakStatements(DumbAllocator& pool, AstGrapher& grapher, Statement* node, BasicBlock* exitNode)
	{
		if (isa<ReturnInst>(exitNode->getTerminator()))
		{
			// We already have return statements. It's not useful to add break statements.
			return;
		}
		
		if (auto sequence = dyn_cast<SequenceNode>(node))
		{
			if (auto graphNode = grapher.getGraphNode(sequence))
			{
				bool hasExitAsSuccessor = any_of(succ_begin(graphNode->exit), succ_end(graphNode->exit), [=](BasicBlock* bb)
				{
					return bb == exitNode;
				});
				
				if (hasExitAsSuccessor)
				{
					TerminatorInst* terminator = graphNode->exit->getTerminator();
					if (BranchInst* branch = dyn_cast<BranchInst>(terminator))
					{
						if (branch->isConditional())
						{
							Expression* condition = pool.allocate<ValueExpression>(*branch->getCondition());
							if (branch->getSuccessor(1) == exitNode)
							{
								condition = logicalNegate(pool, condition);
							}
							IfElseNode* ifThenBreak = pool.allocate<IfElseNode>(condition, BreakNode::breakNode);
							sequence->statements.push_back(ifThenBreak);
						}
						else
						{
							sequence->statements.push_back(BreakNode::breakNode);
						}
					}
					else
					{
						assert(!"Implement other terminators");
					}
				}
			}
			
			for (size_t i = 0; i < sequence->statements.size(); i++)
			{
				recursivelyAddBreakStatements(pool, grapher, sequence->statements[i], exitNode);
			}
		}
		else if (auto ifElse = dyn_cast<IfElseNode>(node))
		{
			recursivelyAddBreakStatements(pool, grapher, ifElse->ifBody, exitNode);
			if (ifElse->elseBody != nullptr)
			{
				recursivelyAddBreakStatements(pool, grapher, ifElse->elseBody, exitNode);
			}
		}
	}
	
	Statement* recursivelySimplifyStatement(DumbAllocator& pool, Statement* statement);
	
	Statement* recursivelySimplifySequence(DumbAllocator& pool, SequenceNode* sequence)
	{
		SequenceNode* simplified = pool.allocate<SequenceNode>(pool);
		for (size_t i = 0; i < sequence->statements.size(); i++)
		{
			Statement* sub = sequence->statements[i];
			Statement* asSimplified = recursivelySimplifyStatement(pool, sub);
			if (auto simplifiedSequence = dyn_cast<SequenceNode>(asSimplified))
			{
				for (size_t j = 0; j < simplifiedSequence->statements.size(); j++)
				{
					simplified->statements.push_back(simplifiedSequence->statements[j]);
				}
			}
			else
			{
				simplified->statements.push_back(asSimplified);
			}
		}
		
		return simplified->statements.size() == 1 ? simplified->statements[0] : simplified;
	}
	
	Statement* recursivelySimplifyIfElse(DumbAllocator& pool, IfElseNode* ifElse)
	{
		while (auto negated = dyn_cast<UnaryOperatorExpression>(ifElse->condition))
		{
			if (negated->type == UnaryOperatorExpression::LogicalNegate && ifElse->elseBody != nullptr)
			{
				ifElse->condition = negated->operand;
				swap(ifElse->ifBody, ifElse->elseBody);
			}
			else
			{
				break;
			}
		}
		
		ifElse->ifBody = recursivelySimplifyStatement(pool, ifElse->ifBody);
		if (ifElse->elseBody != nullptr)
		{
			ifElse->elseBody = recursivelySimplifyStatement(pool, ifElse->elseBody);
		}
		else if (auto childCond = dyn_cast<IfElseNode>(ifElse->ifBody))
		{
			if (childCond->elseBody == nullptr)
			{
				// Neither this if nor the nested if (which is the only child) has an else clause.
				// They can be combined into a single if with an && compound expression.
				Expression* mergedCondition = pool.allocate<BinaryOperatorExpression>(BinaryOperatorExpression::ShortCircuitAnd, ifElse->condition, childCond->condition);
				ifElse->condition = mergedCondition;
				ifElse->ifBody = childCond->ifBody;
			}
		}
		
		return ifElse;
	}
	
	Statement* recursivelySimplifyLoop(DumbAllocator& pool, LoopNode* loop)
	{
		loop->loopBody = recursivelySimplifyStatement(pool, loop->loopBody);
		while (true)
		{
			// The 6 patterns all start with an endless loop.
			if (loop->isEndless())
			{
				if (auto sequence = dyn_cast<SequenceNode>(loop->loopBody))
				{
					size_t lastIndex = sequence->statements.size();
					assert(lastIndex > 0);
					lastIndex--;
					
					// DoWhile
					if (auto ifElse = dyn_cast<IfElseNode>(sequence->statements[lastIndex]))
					{
						if (ifElse->ifBody == BreakNode::breakNode)
						{
							loop->condition = logicalNegate(pool, ifElse->condition);
							loop->position = LoopNode::PostTested;
							sequence->statements.erase_at(lastIndex);
							continue;
						}
					}
					// While, NestedDoWhile
					
					// Pretty sure that LoopToSeq can't happen with our pipeline.
				}
				else if (auto ifElseNode = dyn_cast<IfElseNode>(loop->loopBody))
				{
					// CondToSeq, CondToSeqNeg
				}
			}
			break;
		}
		return loop;
	}
	
	Statement* recursivelySimplifyStatement(DumbAllocator& pool, Statement* statement)
	{
		switch (statement->getType())
		{
			case Statement::Sequence:
				return recursivelySimplifySequence(pool, cast<SequenceNode>(statement));
				
			case Statement::IfElse:
				return recursivelySimplifyIfElse(pool, cast<IfElseNode>(statement));
				
			case Statement::Loop:
				return recursivelySimplifyLoop(pool, cast<LoopNode>(statement));
				
			default: break;
		}
		return statement;
	}
	
	SequenceNode* structurizeRegion(DumbAllocator& pool, AstGrapher& grapher, BasicBlock& entry, BasicBlock& exit, bool includeExit)
	{
		AstGraphNode* astEntry = grapher.getGraphNodeFromEntry(&entry);
		AstGraphNode* astExit = grapher.getGraphNodeFromEntry(&exit);
		
		// Build reaching conditions.
		ReachingConditions reach(pool, grapher);
		reach.build(astEntry, astExit);
		
		// Structure nodes into `if` statements using reaching conditions. Traverse nodes in topological order (reverse
		// postorder). We can't use LLVM's ReversePostOrderTraversal class here because we're working with a subgraph.
		SequenceNode* sequence = pool.allocate<SequenceNode>(pool);
		
		for (Statement* node : reversePostOrder(astEntry, astExit))
		{
			if (!includeExit && node == astExit->node)
			{
				continue;
			}
			
			auto& path = reach.conditions.at(node);
			SmallVector<SmallVector<Expression*, 4>, 4> productOfSums = buildReachingCondition(pool, grapher, path);
			
			// Heuristic: the conditions in productOfSum are returned in traversal order when the simplification code
			// doesn't mess them up too hard. We should be able to get reasonably good output by iterating condition
			// nodes backwards in the sequence.
			// This effectively performs a watered-down version of condition-based refinement and reachability-based
			// refinement. (We don't care that much for switch statements, so condition-aware refinement isn't interesting.)
			SequenceNode* body = sequence;
			for (const auto& sum : productOfSums)
			{
				Expression* condition = collapse(pool, sum, BinaryOperatorExpression::ShortCircuitOr);
				
				// If we find an existing, suitable condition, we can insert the node into the condition to avoid
				// repetition.
				size_t size = body->statements.size();
				if (size > 0)
				{
					if (IfElseNode* conditional = dyn_cast<IfElseNode>(body->statements[size - 1]))
					{
						Expression* thisCondition = conditional->condition;
						bool isSumNegated = false;
						bool isCurrentConditionNegated = false;
						if (auto negatedCond = dyn_cast<UnaryOperatorExpression>(condition))
						{
							if (negatedCond->type == UnaryOperatorExpression::LogicalNegate)
							{
								isSumNegated = true;
								condition = negatedCond->operand;
							}
						}
						if (auto negatedCond = dyn_cast<UnaryOperatorExpression>(thisCondition))
						{
							if (negatedCond->type == UnaryOperatorExpression::LogicalNegate)
							{
								isCurrentConditionNegated = true;
								thisCondition = negatedCond->operand;
							}
						}
						
						if (thisCondition->isReferenceEqual(condition))
						{
							if (isSumNegated == isCurrentConditionNegated)
							{
								// Same condition: insert into if body
								body = cast<SequenceNode>(conditional->ifBody);
							}
							else
							{
								// Inverted condition: insert into else body, create one if it doesn't exist
								if (SequenceNode* elseBody = cast_or_null<SequenceNode>(conditional->elseBody))
								{
									body = elseBody;
								}
								else
								{
									body = pool.allocate<SequenceNode>(pool);
									conditional->elseBody = body;
								}
							}
							continue;
						}
					}
				}
				
				// Otherwise, just create a new node.
				SequenceNode* ifBody = pool.allocate<SequenceNode>(pool);
				auto ifNode = pool.allocate<IfElseNode>(condition, ifBody);
				body->statements.push_back(ifNode);
				body = ifBody;
			}
			
			// body is now the innermost condition body we can add the code to.
			body->statements.push_back(node);
		}
		return sequence;
	}
	
	bool isRegion(DominanceFrontier* frontier, DominatorTree* domTree, BasicBlock& entry, BasicBlock& exit)
	{
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
	
	RegionInfo ri;
	ri.recalculate(fn, domTree, postDomTree, frontier);
	
	auto backNodes = findBackEdgeDestinations(fn.getEntryBlock());
	
	for (BasicBlock* entry : post_order(&fn.getEntryBlock()))
	{
		grapher->addBasicBlock(*entry);
		
		DomTreeNode* domNode = postDomTree->getNode(entry);
		while (DomTreeNode* successor = walkUp(*postDomTree, postDomShortcuts, *domNode))
		{
			if (BasicBlock* exit = successor->getBlock())
			{
				domNode = successor;
				
				if (isRegion(*entry, *exit))
				{
					// Only interpret as a loop if there is a back node AND the region entry has never been
					// part of a region before (otherwise we end up creating nested loops for no reason).
					if (backNodes.count(entry) == 1 && grapher->getGraphNodeFromEntry(entry)->exit == entry)
					{
						changed |= runOnLoop(fn, *entry, *exit);
					}
					else
					{
						changed |= runOnRegion(fn, *entry, *exit);
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
	grapher->getGraphNodeFromEntry(&fn.getEntryBlock())->node->dump();
	return changed;
}

bool AstBackEnd::runOnLoop(Function& fn, BasicBlock& entry, BasicBlock& exit)
{
	// The SESELoop pass already did the meaningful transformations on the loop region:
	// it's now a single-entry, single-exit region, loop membership has already been refined, etc.
	// We really just have to emit the AST.
	// Basically, we want a "while true" loop with break statements wherever we exit the loop scope.
	
	SequenceNode* sequence = structurizeRegion(pool, *grapher, entry, exit, false);
	recursivelyAddBreakStatements(pool, *grapher, sequence, &exit);
	Statement* simplified = recursivelySimplifyStatement(pool, sequence);
	Statement* endlessLoop = pool.allocate<LoopNode>(simplified);
	
	SequenceNode* withExitNode = pool.allocate<SequenceNode>(pool);
	withExitNode->statements.push_back(endlessLoop);
	withExitNode->statements.push_back(grapher->getGraphNodeFromEntry(&exit)->node);
	grapher->updateRegion(entry, exit, *withExitNode);
	return false;
}

bool AstBackEnd::runOnRegion(Function& fn, BasicBlock& entry, BasicBlock& exit)
{
	SequenceNode* sequence = structurizeRegion(pool, *grapher, entry, exit, true);
	Statement* simplified = recursivelySimplifyStatement(pool, sequence);
	grapher->updateRegion(entry, exit, *simplified);
	return false;
}

bool AstBackEnd::isRegion(BasicBlock &entry, BasicBlock &exit)
{
	if (!::isRegion(frontier, domTree, entry, exit))
	{
		return false;
	}
	
	// Set shortcut.
	auto iter = postDomShortcuts.find(&exit);
	postDomShortcuts[&entry] = iter == postDomShortcuts.end() ? &exit : iter->second;
	
	// Exclude so-called trivial regions.
	unsigned successorsCount = entry.getTerminator()->getNumSuccessors();
	if (successorsCount <= 1 && &exit == *succ_begin(&entry))
	{
		return false;
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
