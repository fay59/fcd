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
	
	template<typename TCollection>
	inline Expression* coalesce(DumbAllocator& pool, NAryOperatorExpression::NAryOperatorType type, const TCollection& coll)
	{
		if (coll.size() == 0)
		{
			return nullptr;
		}
		
		if (coll.size() == 1)
		{
			return coll[0];
		}
		
		auto nary = pool.allocate<NAryOperatorExpression>(pool, type);
		for (Expression* exp : coll)
		{
			nary->addOperand(exp);
		}
		return nary;
	}
	
	class ReachingConditions
	{
	public:
		unordered_map<Statement*, SmallVector<SmallVector<Expression*, 4>, 4>> conditions;
		
	private:
		AstGrapher& grapher;
		DumbAllocator& pool;
		
		void build(AstGraphNode* currentNode, SmallVector<Expression*, 4>& conditionStack, vector<AstGraphNode*>& visitStack)
		{
			// Ignore back edges.
			if (find(visitStack.begin(), visitStack.end(), currentNode) != visitStack.end())
			{
				return;
			}
			
			visitStack.push_back(currentNode);
			conditions[currentNode->node].push_back(conditionStack);
			if (currentNode->hasExit())
			{
				// Exit reached by sequentially following structured region. No additional condition here.
				build(grapher.getGraphNodeFromEntry(currentNode->getExit()), conditionStack, visitStack);
			}
			else
			{
				// Exit is unstructured. New conditions may apply.
				auto terminator = currentNode->getEntry()->getTerminator();
				if (auto branch = dyn_cast<BranchInst>(terminator))
				{
					if (branch->isConditional())
					{
						Expression* trueExpr = pool.allocate<ValueExpression>(*branch->getCondition());
						conditionStack.push_back(trueExpr);
						build(grapher.getGraphNodeFromEntry(branch->getSuccessor(0)), conditionStack, visitStack);
						conditionStack.pop_back();
						
						Expression* falseExpr = logicalNegate(pool, trueExpr);
						conditionStack.push_back(falseExpr);
						build(grapher.getGraphNodeFromEntry(branch->getSuccessor(1)), conditionStack, visitStack);
						conditionStack.pop_back();
					}
					else
					{
						// Unconditional branch
						build(grapher.getGraphNodeFromEntry(branch->getSuccessor(0)), conditionStack, visitStack);
					}
				}
				else if (!isa<ReturnInst>(terminator))
				{
					llvm_unreachable("implement missing terminator type");
				}
			}
			visitStack.pop_back();
		}
		
	public:
		
		ReachingConditions(DumbAllocator& pool, AstGrapher& grapher)
		: grapher(grapher), pool(pool)
		{
		}
		
		void buildSumsOfProducts(AstGraphNode* regionStart, AstGraphNode* regionEnd)
		{
			SmallVector<Expression*, 4> expressionStack;
			vector<AstGraphNode*> visitStack { regionEnd };
			build(regionStart, expressionStack, visitStack);
		}
	};
	
	void postOrder(AstGrapher& grapher, vector<Statement*>& into, unordered_set<AstGraphNode*>& visited, AstGraphNode* current, AstGraphNode* exit)
	{
		if (visited.count(current) == 0)
		{
			visited.insert(current);
			if (current->hasExit())
			{
				postOrder(grapher, into, visited, grapher.getGraphNodeFromEntry(current->getExit()), exit);
			}
			else
			{
				for (auto succ : successors(current->getEntry()))
				{
					postOrder(grapher, into, visited, grapher.getGraphNodeFromEntry(succ), exit);
				}
			}
			into.push_back(current->node);
		}
	}
	
	vector<Statement*> reversePostOrder(AstGrapher& grapher, AstGraphNode* entry, AstGraphNode* exit)
	{
		vector<Statement*> result;
		unordered_set<AstGraphNode*> visited { exit };
		postOrder(grapher, result, visited, entry, exit);
		reverse(result.begin(), result.end());
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
	
	void findBackEdges(BasicBlock* entry, deque<BasicBlock*>& stack, unordered_map<BasicBlock*, BasicBlock*>& result)
	{
		stack.push_back(entry);
		for (BasicBlock* bb : successors(entry))
		{
			if (find(stack.rbegin(), stack.rend(), bb) == stack.rend())
			{
				findBackEdges(bb, stack, result);
			}
			else
			{
				result.insert({bb, entry});
			}
		}
		stack.pop_back();
	}
	
	unordered_map<BasicBlock*, BasicBlock*> findBackEdges(BasicBlock& entryPoint)
	{
		unordered_map<BasicBlock*, BasicBlock*> result;
		deque<BasicBlock*> visitedStack;
		findBackEdges(&entryPoint, visitedStack, result);
		return result;
	}
	
	void addBreakStatements(DumbAllocator& pool, AstGrapher& grapher, DominatorTree& domTree, BasicBlock& entryNode, BasicBlock* exitNode)
	{
		if (exitNode == nullptr)
		{
			// Exit is the end of the function. There should already be return statements everywhere required.
			return;
		}
		
		for (BasicBlock* pred : predecessors(exitNode))
		{
			if (domTree.dominates(&entryNode, pred))
			{
				// The sequence for this block will need a break statement.
				auto sequence = cast<SequenceNode>(grapher.getGraphNodeFromEntry(pred)->node);
				auto terminator = pred->getTerminator();
				if (auto branch = dyn_cast<BranchInst>(terminator))
				{
					Statement* breakStatement;
					if (branch->isConditional())
					{
						Expression* cond = pool.allocate<ValueExpression>(*branch->getCondition());
						if (exitNode == branch->getSuccessor(1))
						{
							cond = logicalNegate(pool, cond);
						}
						breakStatement = pool.allocate<IfElseNode>(cond, BreakNode::breakNode);
					}
					else
					{
						breakStatement = BreakNode::breakNode;
					}
					sequence->statements.push_back(breakStatement);
				}
				else
				{
					llvm_unreachable("implement missing terminator type");
				}
			}
		}
	}
	
	bool containsBreakStatement(Statement* statement)
	{
		if (statement == nullptr)
		{
			return false;
		}
		
		if (statement == BreakNode::breakNode)
		{
			return true;
		}
		
		if (auto seq = dyn_cast<SequenceNode>(statement))
		{
			for (size_t i = 0; i < seq->statements.size(); i++)
			{
				if (containsBreakStatement(seq->statements[i]))
					return true;
			}
		}
		else if (auto ifElse = dyn_cast<IfElseNode>(statement))
		{
			return containsBreakStatement(ifElse->ifBody) || containsBreakStatement(ifElse->elseBody);
		}
		
		// Intentionally leaving out while statements, since a break in a while statement will not affect the outer
		// loop.
		return false;
	}
	
	void removeBranch(DumbAllocator& pool, SequenceNode& parent, size_t ifIndex, bool branch)
	{
		branch = !!branch; // make sure that branch is either 0 or 1
		static constexpr Statement* IfElseNode::*branchSelector[] = { &IfElseNode::ifBody, &IfElseNode::elseBody };
		IfElseNode* ifElse = cast<IfElseNode>(parent.statements[ifIndex]);
		ifElse->*branchSelector[branch] = ifElse->*branchSelector[!branch];
		if (ifElse->*branchSelector[branch] != nullptr)
		{
			ifElse->*branchSelector[!branch] = nullptr;
			ifElse->condition = logicalNegate(pool, ifElse->condition);
		}
		else
		{
			parent.statements.erase_at(ifIndex);
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
				auto merged = pool.allocate<NAryOperatorExpression>(pool, NAryOperatorExpression::ShortCircuitAnd);
				merged->addOperand(ifElse->condition);
				merged->addOperand(childCond->condition);
				ifElse->condition = merged;
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
					
					if (auto ifElse = dyn_cast<IfElseNode>(sequence->statements[lastIndex]))
					{
						// DoWhile
						if (ifElse->ifBody == BreakNode::breakNode)
						{
							loop->condition = logicalNegate(pool, ifElse->condition);
							loop->position = LoopNode::PostTested;
							removeBranch(pool, *sequence, lastIndex, true);
							continue;
						}
						else if (ifElse->elseBody == BreakNode::breakNode)
						{
							loop->condition = ifElse->condition;
							loop->position = LoopNode::PostTested;
							removeBranch(pool, *sequence, lastIndex, false);
							continue;
						}
						
						// NestedDoWhile
						if (ifElse->elseBody == nullptr)
						{
							bool hasBreak = false;
							for (size_t i = 0; i < lastIndex; i++)
							{
								if (containsBreakStatement(sequence->statements[i]))
								{
									hasBreak = true;
									break;
								}
							}
							
							if (!hasBreak)
							{
								sequence->statements.erase_at(lastIndex);
								LoopNode* innerLoop = pool.allocate<LoopNode>(sequence);
								innerLoop->condition = logicalNegate(pool, ifElse->condition);
								auto outerLoopBody = pool.allocate<SequenceNode>(pool);
								outerLoopBody->statements.push_back(innerLoop);
								outerLoopBody->statements.push_back(ifElse->ifBody);
								loop->loopBody = outerLoopBody;
								continue;
							}
						}
					}
					
					// While
					if (auto ifElse = dyn_cast<IfElseNode>(sequence->statements[0]))
					{
						if (ifElse->ifBody == BreakNode::breakNode)
						{
							loop->condition = logicalNegate(pool, ifElse->condition);
							loop->position = LoopNode::PreTested;
							removeBranch(pool, *sequence, 0, true);
							continue;
						}
						else if (ifElse->elseBody == BreakNode::breakNode)
						{
							loop->condition = ifElse->condition;
							loop->position = LoopNode::PreTested;
							removeBranch(pool, *sequence, 0, false);
							continue;
						}
					}
					
					// Pretty sure that LoopToSeq can't happen with our pipeline.
				}
				else if (auto ifElse = dyn_cast<IfElseNode>(loop->loopBody))
				{
					// CondToSeq, CondToSeqNeg
					if (ifElse->ifBody != nullptr && ifElse->elseBody != nullptr)
					{
						bool trueHasBreak = containsBreakStatement(ifElse->ifBody);
						bool falseHasBreak = containsBreakStatement(ifElse->elseBody);
						if (trueHasBreak != falseHasBreak)
						{
							LoopNode* innerLoop;
							Statement* next;
							auto outerBody = pool.allocate<SequenceNode>(pool);
							if (falseHasBreak)
							{
								innerLoop = pool.allocate<LoopNode>(ifElse->ifBody);
								innerLoop->condition = ifElse->condition;
								next = ifElse->elseBody;
							}
							else
							{
								innerLoop = pool.allocate<LoopNode>(ifElse->elseBody);
								innerLoop->condition = logicalNegate(pool, ifElse->condition);
								next = ifElse->ifBody;
							}
							outerBody->statements.push_back(innerLoop);
							outerBody->statements.push_back(next);
							loop->loopBody = outerBody;
							continue;
						}
					}
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
	
	SequenceNode* structurizeRegion(DumbAllocator& pool, AstGrapher& grapher, BasicBlock& entry, BasicBlock* exit)
	{
		AstGraphNode* astEntry = grapher.getGraphNodeFromEntry(&entry);
		AstGraphNode* astExit = grapher.getGraphNodeFromEntry(exit);
		
		// Build reaching conditions.
		ReachingConditions reach(pool, grapher);
		reach.buildSumsOfProducts(astEntry, astExit);
		
		// Structure nodes into `if` statements using reaching conditions. Traverse nodes in topological order (reverse
		// postorder). We can't use LLVM's ReversePostOrderTraversal class here because we're working with a subgraph.
		SequenceNode* sequence = pool.allocate<SequenceNode>(pool);
		
		for (Statement* node : reversePostOrder(grapher, astEntry, astExit))
		{
			auto& path = reach.conditions.at(node);
			SmallVector<SmallVector<Expression*, 4>, 4> productOfSums = simplifySumOfProducts(pool, path);
			
			// Heuristic: the conditions in productOfSum are returned in traversal order when the simplification code
			// doesn't mess them up too hard. We should be able to get reasonably good output by iterating condition
			// nodes backwards in the sequence.
			// This effectively performs a watered-down version of condition-based refinement and reachability-based
			// refinement. (We don't care that much for switch statements, so condition-aware refinement isn't interesting.)
			SequenceNode* body = sequence;
			for (const auto& sum : productOfSums)
			{
				auto condition = coalesce(pool, NAryOperatorExpression::ShortCircuitOr, sum);
				
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
	
	auto backNodes = findBackEdges(fn.getEntryBlock());
	
	for (BasicBlock* entry : post_order(&fn.getEntryBlock()))
	{
		DomTreeNode* domNode = postDomTree->getNode(entry);
		DomTreeNode* successor = domNode->getIDom();
		grapher->addBasicBlock(*entry);
		
		while (domNode != nullptr)
		{
			AstGraphNode* graphNode = grapher->getGraphNodeFromEntry(domNode->getBlock());
			successor = postDomTree->getNode(graphNode->getExit());
			if (!graphNode->hasExit())
			{
				successor = successor->getIDom();
			}
			
			BasicBlock* exit = successor ? successor->getBlock() : nullptr;
			if (isRegion(*entry, exit))
			{
				auto backEdgeIter = backNodes.find(entry);
				if (backEdgeIter != backNodes.end())
				{
					changed |= runOnLoop(fn, *entry, exit);
					
					// Only interpret as a loop the first time the node is encountered. Larger regions should be
					// structurized as regions.
					backNodes.erase(entry);
				}
				else
				{
					changed |= runOnRegion(fn, *entry, exit);
				}
			}
			
			if (!domTree->dominates(entry, exit))
			{
				break;
			}
			domNode = successor;
		}
	}
	
	// with lldb and libc++:
	// p grapher.__ptr_.__first_->getGraphNodeFromEntry(&fn.getEntryBlock())->node->dump()
	grapher->getGraphNodeFromEntry(&fn.getEntryBlock())->node->dump();
	return changed;
}

bool AstBackEnd::runOnLoop(Function& fn, BasicBlock& entry, BasicBlock* exit)
{
	// The SESELoop pass already did the meaningful transformations on the loop region:
	// it's now a single-entry, single-exit region, loop membership has already been refined, etc.
	// We really just have to emit the AST.
	// Basically, we want a "while true" loop with break statements wherever we exit the loop scope.
	
	SequenceNode* sequence = structurizeRegion(pool, *grapher, entry, exit);
	addBreakStatements(pool, *grapher, *domTree, entry, exit);
	Statement* simplified = recursivelySimplifyStatement(pool, sequence);
	Statement* endlessLoop = pool.allocate<LoopNode>(simplified);
	grapher->updateRegion(entry, exit, *endlessLoop);
	return false;
}

bool AstBackEnd::runOnRegion(Function& fn, BasicBlock& entry, BasicBlock* exit)
{
	SequenceNode* sequence = structurizeRegion(pool, *grapher, entry, exit);
	Statement* simplified = recursivelySimplifyStatement(pool, sequence);
	grapher->updateRegion(entry, exit, *simplified);
	return false;
}

bool AstBackEnd::isRegion(BasicBlock &entry, BasicBlock *exit)
{
	// LLVM's algorithm for finding regions (as of this early LLVM 3.7 fork) seems broken. For instance, with the
	// following graph:
	//
	//   0
	//   |\
	//   | 1
	//   | |
	//   | 2=<|    (where =<| denotes an edge to itself)
	//   |/
	//   3
	//
	// LLVM thinks that BBs 2 and 3 form a region. This appears incorrect.
	// Sine the classical definition of regions apply to edges and edges are second-class citizens in the LLVM graph
	// world, we're going to roll with this HORRIBLY inefficient (but working), home-baked definition instead:
	//
	// A region is an ordered pair (A, B) of nodes, where A dominates, and B postdominates, every node
	// traversed in any given iteration order from A to B. Additionally, no path starts after B such that a node of the
	// region can be reached again without traversing A.
	// This definition means that B is *excluded* from the region, because B could have predecessors that are not
	// dominated by A. And I'm okay with it, I like [) ranges. To compensate, nullptr represents the end of a function.
	
	unordered_set<BasicBlock*> toVisit { &entry };
	unordered_set<BasicBlock*> visited { exit };
	// Step one: check domination
	while (toVisit.size() > 0)
	{
		auto iter = toVisit.begin();
		BasicBlock* bb = *iter;
		
		// In our case, nullptr denotes the end of the function, which dominates everything.
		// (The standard behavior is that nullptr is "unreachable", and dominates nothing.)
		if (!domTree->dominates(&entry, bb) || (exit != nullptr && !postDomTree->dominates(exit, bb)))
		{
			return false;
		}
		
		toVisit.erase(iter);
		visited.insert(bb);
		for (BasicBlock* succ : successors(bb))
		{
			if (visited.count(succ) == 0)
			{
				toVisit.insert(succ);
			}
		}
	}
	
	// Step two: check that no path starting after the exit goes back into the region without first going through the
	// entry.
	unordered_set<BasicBlock*> regionMembers;
	regionMembers.swap(visited);
	
	if (exit != nullptr)
	{
		toVisit.insert(succ_begin(exit), succ_end(exit));
	}
	
	visited.insert(&entry);
	while (toVisit.size() > 0)
	{
		auto iter = toVisit.begin();
		BasicBlock* bb = *iter;
		
		if (regionMembers.count(bb) != 0)
		{
			return false;
		}
		
		toVisit.erase(iter);
		visited.insert(bb);
		for (BasicBlock* succ : successors(bb))
		{
			if (visited.count(succ) == 0)
			{
				toVisit.insert(succ);
			}
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
