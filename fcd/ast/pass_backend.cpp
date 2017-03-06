//
// pass_backend.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "metadata.h"
#include "passes.h"
#include "pass_backend.h"
#include "pre_ast_cfg.h"

#include <llvm/ADT/PostOrderIterator.h>
#include <llvm/ADT/SCCIterator.h>
#include <llvm/Analysis/DominanceFrontierImpl.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_os_ostream.h>

#include <algorithm>
#include <deque>
#include <list>
#include <vector>

using namespace llvm;
using namespace std;

namespace
{
	uint64_t getVirtualAddress(FunctionNode& node)
	{
		if (auto address = md::getVirtualAddress(node.getFunction()))
		{
			return address->getLimitedValue();
		}
		return 0;
	}
	
	struct DfsStackItem
	{
		PreAstBasicBlock& block;
		typedef decltype(block.successors)::iterator block_iterator;
		block_iterator current;
		
		DfsStackItem(PreAstBasicBlock& block)
		: block(block), current(block.successors.begin())
		{
		}
		
		block_iterator end()
		{
			return block.successors.end();
		}
	};
	
	void ensureLoopsExit(PreAstContext& function)
	{
		// This ensures that every loop has an exit for the purpose of calculating the post-dominator tree.
		for (auto iter = scc_begin(&function); iter != scc_end(&function); ++iter)
		{
			if (iter.hasLoop())
			{
				bool hasOutsideSuccessor = false;
				SmallPtrSet<PreAstBasicBlock*, 16> loopMembers(iter->begin(), iter->end());
				for (auto block : *iter)
				{
					hasOutsideSuccessor = any_of(block->successors, [&](PreAstBasicBlockEdge* edge)
					{
						return loopMembers.count(edge->to) == 0;
					});
					
					if (hasOutsideSuccessor)
					{
						break;
					}
				}
				
				if (!hasOutsideSuccessor)
				{
					for (auto block : *iter)
					{
						auto outsidePredecessorIter = find_if(block->predecessors, [&](PreAstBasicBlockEdge* edge)
						{
							return loopMembers.count(edge->from) == 0;
						});
						
						if (outsidePredecessorIter != block->predecessors.end())
						{
							// Insert a fake edge going to a fake exit edge from any entry block. This helps the post-dominator tree.
							PreAstBasicBlock& fakeExit = function.createBlock();
							PreAstBasicBlockEdge& fakeEdge = function.createEdge(*block, fakeExit, *function.getContext().expressionForFalse());
							fakeExit.predecessors.push_back(&fakeEdge);
							block->successors.push_back(&fakeEdge);
							break;
						}
					}
				}
			}
		}
	}
	
	bool derefEqual(const Expression* a, const Expression* b)
	{
		return *a == *b;
	}
	
	class Structurizer
	{
	public:
		typedef PreAstBasicBlockRegionTraits::DomTreeT DomTree;
		typedef PreAstBasicBlockRegionTraits::PostDomTreeT PostDomTree;
		typedef PreAstBasicBlockRegionTraits::DomFrontierT DomFrontier;
		
	private:
		AstContext& ctx;
		PreAstContext& function;
		DomTree& domTree;
		PostDomTree& postDomTree;
		DomFrontier& domFrontier;
		list<PreAstBasicBlock*> blocksInReversePostOrder;
		typedef decltype(blocksInReversePostOrder)::iterator block_iterator;
		
		bool isRegion(PreAstBasicBlock* entry, PreAstBasicBlock* exit)
		{
			typedef PreAstBasicBlockRegionTraits::DomFrontierT::DomSetType DomSetType;
			
			DomSetType& entrySuccessors = domFrontier.find(entry)->second;
			
			// If the exit is the header of a loop that contains the entry, the dominance frontier must only contain the
			// exit.
			if (!domTree.dominates(entry, exit))
			{
				bool onlyEntryOrExit = all_of(entrySuccessors, [=](PreAstBasicBlock* frontierBlock)
				{
					return frontierBlock == entry || frontierBlock == exit;
				});
				if (!onlyEntryOrExit)
				{
					return false;
				}
			}
			
			DomSetType& exitSuccessors = domFrontier.find(exit)->second;
			// Do not allow edges to leave the region.
			for (PreAstBasicBlock* entrySuccessor : entrySuccessors)
			{
				if (entrySuccessor == entry || entrySuccessor == exit)
				{
					continue;
				}
				
				if (exitSuccessors.count(entrySuccessor) == 0)
				{
					return false;
				}
				
				bool domFrontierNotCommon = any_of(entrySuccessor->predecessors, [&](PreAstBasicBlockEdge* edge)
				{
					return domTree.dominates(entry, edge->from) && !domTree.dominates(exit, edge->from);
				});
				if (domFrontierNotCommon)
				{
					return false;
				}
			}
			
			// Do not allow edges pointing into the region.
			for (PreAstBasicBlock* exitSuccessor : exitSuccessors)
			{
				if (domTree.properlyDominates(entry, exitSuccessor) && exitSuccessor != exit)
				{
					return false;
				}
			}
			
			return true;
		}
		
		bool regionContains(PreAstBasicBlock* entry, PreAstBasicBlock* exit, PreAstBasicBlock* block)
		{
			if (domTree.getNode(block) == nullptr)
			{
				return false;
			}
			
			if (exit == nullptr)
			{
				// top-level region contains everything
				return true;
			}
			
			return domTree.dominates(entry, block) && !(domTree.dominates(exit, block) && domTree.dominates(entry, exit));
		}
		
		Statement* foldBasicBlocks(block_iterator begin, block_iterator end)
		{
			// Fold blocks into one sequence. This is easy now that we can just iterate over the region range, which is
			// sorted in post order.
			SequenceStatement* resultSequence = ctx.sequence();
			SmallDenseMap<PreAstBasicBlock*, SmallVector<SmallVector<Expression*, 4>, 8>> reachingConditions;
			
			bool isLoop = false;
			SmallPtrSet<PreAstBasicBlock*, 16> memberBlocks;
			for (PreAstBasicBlock* bb : make_range(begin, end))
			{
				// Identify back-edges. If we find any back-edge, we know that we have to wrap this region in a loop
				// and insert break statements.
				memberBlocks.insert(bb);
				if (!isLoop)
				{
					for (auto succEdge : bb->successors)
					{
						if (memberBlocks.count(succEdge->to))
						{
							isLoop = true;
							break;
						}
					}
				}
				
				// Create reaching condition and insert block in larger sequence.
				auto result = reachingConditions.insert({bb, {}});
				assert(result.second); (void) result;
				
				auto& disjunction = result.first->second;
				for (auto predEdge : bb->predecessors)
				{
					// Only consider the edge condition for blocks that we have visited already. This saves us from
					// getting the entry condition for the region's entry block (we don't want it because entry is
					// unconditional), and loop back-edges (the edge condition should be applied to a break statement).
					if (predEdge->from == bb)
					{
						continue;
					}
					auto iter = reachingConditions.find(predEdge->from);
					if (iter != reachingConditions.end())
					{
						if (iter->second.size() == 0)
						{
							// The parent was reached unconditionally. It has no paths instead of one path with true,
							// so just insert one path with the reaching condition (if it is not unconditonal itself).
							if (predEdge->edgeCondition != ctx.expressionForTrue())
							{
								disjunction.push_back({predEdge->edgeCondition});
							}
						}
						else
						{
							auto startIter = disjunction.insert(disjunction.end(), iter->second.begin(), iter->second.end());
							if (predEdge->edgeCondition != ctx.expressionForTrue())
							{
								for (auto appendIter = startIter; appendIter != disjunction.end(); ++appendIter)
								{
									appendIter->push_back(predEdge->edgeCondition);
								}
							}
						}
					}
				}
				
				// Ensure that bb->blockStatement is a sequence. It needs to be a sequence to add break statements
				// later if necessary.
				if (bb->blockStatement == nullptr)
				{
					bb->blockStatement = ctx.sequence();
				}
				else if (!isa<SequenceStatement>(bb->blockStatement))
				{
					auto seq = ctx.sequence();
					seq->pushBack(bb->blockStatement);
					bb->blockStatement = seq;
				}
				
				Statement* statementToInsert = bb->blockStatement;
				if (disjunction.size() > 0)
				{
					// Collect common condition prefix and suffix.
					auto orIter = disjunction.begin();
					auto commonPrefix = *orIter;
					auto commonSuffix = *orIter;
					for (++orIter; orIter != disjunction.end(); ++orIter)
					{
						auto prefixMismatch = mismatch(commonPrefix.begin(), commonPrefix.end(), orIter->begin(), orIter->end(), derefEqual);
						commonPrefix.erase(prefixMismatch.first, commonPrefix.end());
						
						auto suffixMismatch = mismatch(commonSuffix.rbegin(), commonSuffix.rend(), orIter->rbegin(), orIter->rend(), derefEqual);
						commonSuffix.erase(commonSuffix.begin(), suffixMismatch.first.base());
					}
					
					if (commonPrefix.size() == disjunction.front().size())
					{
						// Identical condition, clear commonSuffix so that we don't duplicate anything.
						commonSuffix.clear();
					}
					
					// Create OR-joined condition with condition parts after the prefix.
					SmallVector<Expression*, 4> disjunctionTerms;
					for (auto& andSequence : disjunction)
					{
						if (andSequence.size() != commonPrefix.size() + commonSuffix.size())
						{
							auto copyBegin = andSequence.begin() + commonPrefix.size();
							auto copyEnd = andSequence.end() - commonSuffix.size();
							auto copySize = copyEnd - copyBegin;
							if (copySize == 1)
							{
								disjunctionTerms.push_back(*copyBegin);
							}
							else if (copySize != 0)
							{
								Expression* subsequence = ctx.nary(NAryOperatorExpression::ShortCircuitAnd, copyBegin, copyEnd);
								disjunctionTerms.push_back(subsequence);
							}
						}
					}
					
					// Nest into if statements for easy merging by the branch combining pass.
					if (disjunctionTerms.size() > 0)
					{
						Expression* disjunctionExpression = ctx.nary(NAryOperatorExpression::ShortCircuitOr, disjunctionTerms.rbegin(), disjunctionTerms.rend());
						statementToInsert = ctx.ifElse(disjunctionExpression, statementToInsert);
					}
					for (Expression* term : make_range(commonSuffix.rbegin(), commonSuffix.rend()))
					{
						statementToInsert = ctx.ifElse(term, statementToInsert);
					}
					for (Expression* term : make_range(commonPrefix.rbegin(), commonPrefix.rend()))
					{
						statementToInsert = ctx.ifElse(term, statementToInsert);
					}
				}
			
				resultSequence->pushBack(statementToInsert);
			}
			
			if (isLoop)
			{
				PreAstBasicBlock* loopExit = nullptr;
				for (PreAstBasicBlock* bb : make_range(begin, end))
				{
					for (auto edge : bb->successors)
					{
						if (memberBlocks.count(edge->to) == 0)
						{
							loopExit = edge->to;
							break;
						}
					}
				}
				
				if (loopExit != nullptr)
				{
					for (PreAstBasicBlockEdge* exitingEdge : loopExit->predecessors)
					{
						PreAstBasicBlock& predecessor = *exitingEdge->from;
						if (memberBlocks.count(&predecessor) > 0)
						{
							Statement* conditionalBreak = ctx.breakStatement(exitingEdge->edgeCondition);
							cast<SequenceStatement>(predecessor.blockStatement)->pushBack(conditionalBreak);
						}
					}
				}
				return ctx.loop(ctx.expressionForTrue(), LoopStatement::PreTested, resultSequence);
			}
			else
			{
				return resultSequence;
			}
		}
		
		// This function splits a single region in up to 3 regions. The new regions are:
		// entry -> return.first
		// return.first -> return.second
		// return.second -> exit
		Statement* splitAndFoldRegion(block_iterator entry, block_iterator exit)
		{
			SmallPtrSet<PreAstBasicBlock*, 8> allBlocks;
			auto blocksEnd = blocksInReversePostOrder.end();
			if (exit == blocksEnd)
			{
				allBlocks.insert(blocksInReversePostOrder.begin(), blocksInReversePostOrder.end());
			}
			
			// Do a depth-first search to identify loop nodes.
			unordered_set<PreAstBasicBlock*> loopNodes;
			unordered_set<PreAstBasicBlock*> regionNodes { *entry };
			deque<PreAstBasicBlock*> orderedLoopNodes;
			deque<PreAstBasicBlock*> orderedRegionNodes { *entry };
			SmallVector<PreAstBasicBlockEdge*, 4> backEdges;
			deque<DfsStackItem> dfsStack;
			dfsStack.emplace_back(**entry);
			
			while (!dfsStack.empty())
			{
				DfsStackItem& top = dfsStack.back();
				if (top.current == top.end())
				{
					dfsStack.pop_back();
					continue;
				}
				
				PreAstBasicBlockEdge* edge = *top.current;
				++top.current;
				
				// Do not traverse blocks that are outside of this region. This means that we have to stop when we get
				// to the exit. If the exit is the end iterator, then we are in the presence of a loop, and we have to
				// stop whenever we see a block that hasn't been visited by the region algorithm yet.
				if (allBlocks.count(edge->to) == 0)
				{
					continue;
				}
				else if (exit != blocksEnd && *exit == edge->to)
				{
					continue;
				}
				
				if (regionNodes.insert(edge->to).second)
				{
					orderedRegionNodes.push_back(edge->to);
				}
				
				auto edgeToIter = find_if(dfsStack, [&](DfsStackItem& item) { return &item.block == edge->to; });
				if (edgeToIter != dfsStack.end())
				{
					backEdges.push_back(edge);
				}
				
				if (edgeToIter != dfsStack.end() || loopNodes.count(edge->to) != 0)
				{
					for (auto& item : dfsStack)
					{
						if (loopNodes.insert(&item.block).second)
						{
							orderedLoopNodes.push_back(&item.block);
						}
					}
				}
				else
				{
					dfsStack.emplace_back(*edge->to);
				}
			}
			
			if (loopNodes.size() == 0)
			{
				return foldBasicBlocks(entry, exit);
			}
			
			// The loop successor refinement phase has questionable results on lots of programs, and it's really messy if
			// you want deterministic output. Revisit later if necessary.
			
			// Collect entering and exiting edges.
			SmallVector<PreAstBasicBlockEdge*, 4> exitingEdges;
			SmallVector<PreAstBasicBlockEdge*, 4> enteringEdges(backEdges.begin(), backEdges.end());
			for (PreAstBasicBlock* block : orderedLoopNodes)
			{
				for (PreAstBasicBlockEdge* edge : block->predecessors)
				{
					if (loopNodes.count(edge->from) == 0)
					{
						enteringEdges.push_back(edge);
					}
				}
				
				for (PreAstBasicBlockEdge* edge : block->successors)
				{
					if (loopNodes.count(edge->to) == 0)
					{
						exitingEdges.push_back(edge);
					}
				}
			}
			
			// Do we need to create an entry block?
			block_iterator loopEntry = entry;
			for (PreAstBasicBlockEdge*& edge : enteringEdges)
			{
				// The position of the new entry block in the basic block list is quite a big deal. We don't need to
				// care much about the position of the exit, for instance, because it's pretty much guaranteed to be
				// swallowed. The entry, however, is returned.
				if (&edge != &enteringEdges.front() && edge->to != enteringEdges.front()->to)
				{
					PreAstBasicBlock* newEntry = &function.createRedirectorBlock(enteringEdges);
					if (loopNodes.count(*entry) == 0)
					{
						// Insert new block before the first loop node.
						auto insertPosition = find_if(blocksInReversePostOrder, [&](PreAstBasicBlock* block)
						{
							return loopNodes.count(block) != 0;
						});
						loopEntry = blocksInReversePostOrder.insert(insertPosition, newEntry);
					}
					else
					{
						// This is weird: the entry block *has* to remain the block that was first in
						// blocksInReversePostOrder, because the collection has to be in sync with the post-dominator
						// tree (and any block that we create at this point cannot be in the post-dominator tree). As a
						// consequence, to create a new entry, we need to swap the memory contents (and edge references)
						// of the block that we create with the entry that we currently have.
						// Insert the block after the first entry.
						newEntry->swap(**entry);
						auto insertPosition = entry;
						++insertPosition;
						loopEntry = blocksInReversePostOrder.insert(insertPosition, newEntry);
					}
					break;
				}
			}
			
			// Do we need to create an exit block?
			block_iterator loopExit = exit;
			for (PreAstBasicBlockEdge*& edge : exitingEdges)
			{
				if (&edge != &exitingEdges.front() && edge->to != exitingEdges.front()->to)
				{
					PreAstBasicBlock* exitBlock = &function.createRedirectorBlock(exitingEdges);
					loopExit = blocksInReversePostOrder.insert(find(blocksInReversePostOrder, exitingEdges.back()->from), exitBlock);
					break;
				}
			}
			
			SequenceStatement* result = ctx.sequence();
			if (loopEntry != entry)
			{
				result->pushBack(foldBasicBlocks(entry, loopEntry));
			}
			
			result->pushBack(foldBasicBlocks(loopEntry, loopExit));
			
			if (loopExit != exit)
			{
				result->pushBack(foldBasicBlocks(loopExit, exit));
			}
			
			return result;
		}
		
		bool reduceRegion(PreAstBasicBlock* exit)
		{
			size_t regionSize = 0;
			PreAstBasicBlock* entry = blocksInReversePostOrder.front();
			block_iterator exitIter = blocksInReversePostOrder.end();
			block_iterator endIter = blocksInReversePostOrder.end();
			// Calculate region range and move exit after region (if necessary).
			for (auto iter = blocksInReversePostOrder.begin(); iter != blocksInReversePostOrder.end(); ++iter)
			{
				if (*iter == exit)
				{
					exitIter = iter;
				}
				else if (!regionContains(entry, exit, *iter))
				{
					endIter = iter;
					break;
				}
				else
				{
					++regionSize;
				}
			}
			
			if (regionSize == 1)
			{
				// Don't waste time on single-block regions, unless they loop.
				bool hasLoop = any_of(entry->successors, [=](PreAstBasicBlockEdge* edge) {
					return edge->to == entry;
				});
				if (!hasLoop)
				{
					return false;
				}
			}
			
			if (exitIter != blocksInReversePostOrder.end())
			{
				endIter = blocksInReversePostOrder.insert(endIter, *exitIter);
				blocksInReversePostOrder.erase(exitIter);
			}
			
			entry->blockStatement = splitAndFoldRegion(blocksInReversePostOrder.begin(), endIter);
			
			// Clear the successors of every block in that region. (We need to do it at least on the entry node, and
			// doing it on the other nodes help show better graphs using PreAstContext::view().)
			for (PreAstBasicBlock* block : make_range(blocksInReversePostOrder.begin(), endIter))
			{
				for (auto edge : block->successors)
				{
					auto eraseIter = remove(edge->to->predecessors.begin(), edge->to->predecessors.end(), edge);
					edge->to->predecessors.erase(eraseIter);
				}
				block->successors.clear();
			}
			
			// Merge outgoing edges to the same block into one single edge with 'true' as the condition.
			if (exit != nullptr)
			{
				auto predIter = exit->predecessors.begin();
				while (predIter != exit->predecessors.end())
				{
					// This leaves unreachable nodes pointing to exit, but we're going to get rid of the graph anyway.
					if (regionContains(entry, exit, (*predIter)->from))
					{
						predIter = exit->predecessors.erase(predIter);
					}
					else
					{
						++predIter;
					}
				}
				auto& newExitEdge = function.createEdge(*entry, *exit, *ctx.expressionForTrue());
				entry->successors.push_back(&newExitEdge);
				exit->predecessors.push_back(&newExitEdge);
			}
			
			auto beginErase = blocksInReversePostOrder.begin();
			++beginErase;
			blocksInReversePostOrder.erase(beginErase, endIter);
			
			return true;
		}
		
	public:
		Structurizer(PreAstContext& function, DomTree& domTree, PostDomTree& postDomTree, DomFrontier& domFrontier)
		: ctx(function.getContext()), function(function), domTree(domTree), postDomTree(postDomTree), domFrontier(domFrontier)
		{
		}
		
		Statement* structurizeFunction()
		{
			for (PreAstBasicBlock* entry : post_order(&function))
			{
				blocksInReversePostOrder.push_front(entry);
				
				// "entry" is only a possible entry if this test passes.
				if (auto entryPostDomNode = postDomTree.getNode(entry))
				{
					auto parent = entryPostDomNode->getIDom();
					while (parent != nullptr)
					{
						auto exit = parent->getBlock();
						parent = parent->getIDom();
						if (exit != nullptr)
						{
							if (isRegion(entry, exit))
							{
								reduceRegion(exit);
							}
							
							if (!domTree.dominates(entry, exit))
							{
								break;
							}
						}
					}
				}
			}
			
			reduceRegion(nullptr);
			assert(blocksInReversePostOrder.size() == 1);
			return blocksInReversePostOrder.front()->blockStatement;
		}
	};
}

#pragma mark - AST Pass
char AstBackEnd::ID = 0;
static RegisterPass<AstBackEnd> astBackEnd("-ast-backend", "Produce AST from LLVM module");

AstBackEnd::AstBackEnd()
: ModulePass(ID)
{
}

AstBackEnd::~AstBackEnd()
{
}

void AstBackEnd::getAnalysisUsage(llvm::AnalysisUsage &au) const
{
	au.setPreservesAll();
}

void AstBackEnd::addPass(AstModulePass *pass)
{
	assert(pass != nullptr);
	passes.emplace_back(pass);
}

bool AstBackEnd::runOnModule(llvm::Module &m)
{
	outputNodes.clear();
	
	for (Function& fn : m)
	{
		outputNodes.emplace_back(new FunctionNode(fn));
		output = outputNodes.back().get();
		if (!md::isPrototype(fn))
		{
			runOnFunction(fn);
		}
	}
	
	// sort outputNodes by virtual address, then by name
	sort(outputNodes.begin(), outputNodes.end(), [](unique_ptr<FunctionNode>& a, unique_ptr<FunctionNode>& b)
	{
		auto virtA = getVirtualAddress(*a);
		auto virtB = getVirtualAddress(*b);
		if (virtA < virtB)
		{
			return true;
		}
		else if (virtA == virtB)
		{
			return a->getFunction().getName() < b->getFunction().getName();
		}
		else
		{
			return false;
		}
	});
	
	// run passes
	for (auto& pass : passes)
	{
		pass->run(outputNodes);
	}
	
	return false;
}

void AstBackEnd::runOnFunction(Function& fn)
{
	// Create AST block graph.
	outputNodes.emplace_back(new FunctionNode(fn));
	FunctionNode& result = *outputNodes.back();
	blockGraph.reset(new PreAstContext(result.getContext()));
	blockGraph->generateBlocks(fn);
	
	// Ensure that loops all have an exit node, for the sake of the post-dominator tree.
	ensureLoopsExit(*blockGraph);
	
	// Compute regions.
	PreAstBasicBlockRegionTraits::DomTreeT domTree(false);
	PreAstBasicBlockRegionTraits::PostDomTreeT postDomTree(true);
	PreAstBasicBlockRegionTraits::DomFrontierT dominanceFrontier;
	domTree.recalculate(*blockGraph);
	postDomTree.recalculate(*blockGraph);
	dominanceFrontier.analyze(domTree);
	Structurizer structurizer(*blockGraph, domTree, postDomTree, dominanceFrontier);
	auto body = structurizer.structurizeFunction();
	
	result.setBody(body);
}

AstBackEnd* createAstBackEnd()
{
	return new AstBackEnd;
}
