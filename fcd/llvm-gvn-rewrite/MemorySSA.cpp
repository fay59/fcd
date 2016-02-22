//===-- MemorySSA.cpp - Memory SSA Builder---------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------===//
//
// This file implements the MemorySSA class.
//
//===----------------------------------------------------------------===//
#include "llvm/Transforms/Scalar.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/GraphTraits.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/Analysis/IteratedDominanceFrontier.h"
#include "llvm/Analysis/MemoryLocation.h"
#include "llvm/Analysis/PHITransAddr.h"
#include "llvm/IR/AssemblyAnnotationWriter.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PatternMatch.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/FormattedStream.h"
#include "MemorySSA.h"
#include <algorithm>
#include <queue>

#define DEBUG_TYPE "memoryssa"
using namespace llvm;
STATISTIC(NumClobberCacheLookups, "Number of Memory SSA version cache lookups");
STATISTIC(NumClobberCacheHits, "Number of Memory SSA version cache hits");
STATISTIC(NumClobberCacheInserts, "Number of MemorySSA version cache inserts");
INITIALIZE_PASS_WITH_OPTIONS_BEGIN(MemorySSAPrinterPass, "print-memoryssa",
								   "Memory SSA", true, true)
INITIALIZE_AG_DEPENDENCY(AliasAnalysis)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_END(MemorySSAPrinterPass, "print-memoryssa", "Memory SSA", true,
					true)

INITIALIZE_PASS(MemorySSALazy, "memoryssalazy", "Memory SSA", true, true)

namespace llvm {
	
	/// \brief An annotator class to print Memory SSA information in comments.
	class MemorySSAAnnotatedWriter : public AssemblyAnnotationWriter {
  friend class MemorySSA;
  const MemorySSA *MSSA;
		
	public:
  MemorySSAAnnotatedWriter(const MemorySSA *M) : MSSA(M) {}
		
  virtual void emitBasicBlockStartAnnot(const BasicBlock *BB,
										formatted_raw_ostream &OS) {
	  MemoryAccess *MA = MSSA->getMemoryAccess(BB);
	  if (MA)
		  OS << "; " << *MA << "\n";
  }
		
  virtual void emitInstructionAnnot(const Instruction *I,
									formatted_raw_ostream &OS) {
	  MemoryAccess *MA = MSSA->getMemoryAccess(I);
	  if (MA)
		  OS << "; " << *MA << "\n";
  }
	};
}

namespace {
	struct RenamePassData {
  DomTreeNode *DTN;
  DomTreeNode::const_iterator ChildIt;
  MemoryAccess *IncomingVal;
		
  RenamePassData(DomTreeNode *D, DomTreeNode::const_iterator It,
				 MemoryAccess *M)
		: DTN(D), ChildIt(It), IncomingVal(M) {}
  void swap(RenamePassData &RHS) {
	  std::swap(DTN, RHS.DTN);
	  std::swap(ChildIt, RHS.ChildIt);
	  std::swap(IncomingVal, RHS.IncomingVal);
  }
	};
}

namespace llvm {
	
	/// \brief Rename a single basic block into MemorySSA form.
	/// Uses the standard SSA renaming algorithm.
	/// \returns The new incoming value.
	MemoryAccess *MemorySSA::renameBlock(BasicBlock *BB, MemoryAccess *IncomingVal,
										 MemorySSAWalker *Walker) {
  auto It = PerBlockAccesses.find(BB);
  // Skip if the list is empty, but we still have to pass thru the
  // incoming value info/etc to successors
  if (It != PerBlockAccesses.end()) {
	  auto &Accesses = It->second;
	  for (auto &L : *Accesses) {
		  if (isa<MemoryPhi>(L)) {
			  IncomingVal = &L;
		  } else if (MemoryUse *MU = dyn_cast<MemoryUse>(&L)) {
			  MU->setDefiningAccess(IncomingVal);
		  } else if (MemoryDef *MD = dyn_cast<MemoryDef>(&L)) {
			  // We can't legally optimize defs, because we only allow single
			  // memory phis/uses on operations, and if we optimize these, we can
			  // end up with multiple reaching defs.  Uses do not have this
			  // problem, since they do not produce a value
			  MD->setDefiningAccess(IncomingVal);
			  IncomingVal = MD;
		  }
	  }
  }
		
  for (auto S : successors(BB)) {
	  auto It = PerBlockAccesses.find(S);
	  // Rename the phi nodes in our successor block
	  if (It != PerBlockAccesses.end() && isa<MemoryPhi>(It->second->front())) {
		  auto &Accesses = It->second;
		  MemoryPhi *Phi = cast<MemoryPhi>(&Accesses->front());
		  int NumEdges = std::count(succ_begin(BB), succ_end(BB), S);
		  assert(NumEdges && "Must be at least one edge from Succ to BB!");
		  for (unsigned i = 0; i != NumEdges; ++i)
			  Phi->addIncoming(IncomingVal, BB);
	  }
  }
  return IncomingVal;
	}
	
	/// \brief This is the standard SSA renaming algorithm.
	///
	/// We walk the dominator tree in preorder, renaming accesses, and then filling
	/// in phi nodes in our successors.
	void MemorySSA::renamePass(DomTreeNode *Root, MemoryAccess *IncomingVal,
							   SmallPtrSet<BasicBlock *, 16> &Visited,
							   MemorySSAWalker *Walker) {
  SmallVector<RenamePassData, 32> WorkStack;
  IncomingVal = renameBlock(Root->getBlock(), IncomingVal, Walker);
  WorkStack.push_back({Root, Root->begin(), IncomingVal});
  Visited.insert(Root->getBlock());
		
  while (!WorkStack.empty()) {
	  DomTreeNode *Node = WorkStack.back().DTN;
	  DomTreeNode::const_iterator ChildIt = WorkStack.back().ChildIt;
	  IncomingVal = WorkStack.back().IncomingVal;
	  
	  if (ChildIt == Node->end()) {
		  WorkStack.pop_back();
	  } else {
		  DomTreeNode *Child = *ChildIt;
		  ++WorkStack.back().ChildIt;
		  BasicBlock *BB = Child->getBlock();
		  Visited.insert(BB);
		  IncomingVal = renameBlock(BB, IncomingVal, Walker);
		  WorkStack.push_back({Child, Child->begin(), IncomingVal});
	  }
  }
	}
	
	/// \brief Compute dominator levels, used by the phi insertion algorithm above.
	void MemorySSA::computeDomLevels(DenseMap<DomTreeNode *, unsigned> &DomLevels) {
  for (auto DFI = df_begin(DT->getRootNode()), DFE = df_end(DT->getRootNode());
	   DFI != DFE; ++DFI)
	  DomLevels[*DFI] = DFI.getPathLength() - 1;
	}
	
	/// \brief This handles unreachable block acccesses by deleting phi nodes in
	/// unreachable blocks, and marking all other unreachable MemoryAccess's as
	/// being uses of the live on entry definition.
	void MemorySSA::markUnreachableAsLiveOnEntry(BasicBlock *BB) {
  assert(!DT->isReachableFromEntry(BB) &&
		 "Reachable block found while handling unreachable blocks");
		
  auto It = PerBlockAccesses.find(BB);
  if (It == PerBlockAccesses.end())
	  return;
		
  auto &Accesses = It->second;
  for (auto AI = Accesses->begin(), AE = Accesses->end(); AI != AE;) {
	  auto Next = std::next(AI);
	  // If we have a phi, just remove it. We are going to replace all
	  // users with live on entry.
	  if (isa<MemoryPhi>(&*AI)) {
		  Accesses->erase(AI);
	  } else {
		  AI->setDefiningAccess(LiveOnEntryDef);
	  }
	  AI = Next;
  }
	}
	
	MemorySSA::MemorySSA(Function &Func)
	: F(Func), LiveOnEntryDef(nullptr), nextID(0), builtAlready(false),
	Walker(nullptr) {}
	
	MemorySSA::~MemorySSA() {
  InstructionToMemoryAccess.clear();
  PerBlockAccesses.clear();
  delete LiveOnEntryDef;
	}
	std::unique_ptr<MemorySSA::AccessListType> &
	MemorySSA::getOrCreateAccessList(BasicBlock *BB) {
  auto Res = PerBlockAccesses.insert(std::make_pair(BB, nullptr));
  if (Res.second) {
	  Res.first->second = make_unique<AccessListType>(); // AccessListType();
  }
  return Res.first->second;
	}
	
	MemorySSAWalker *MemorySSA::buildMemorySSA(AliasAnalysis *AA,
											   DominatorTree *DT) {
  if (builtAlready)
	  return Walker;
  else
	  Walker = new CachingMemorySSAWalker(this, AA, DT);
		
  this->AA = AA;
  this->DT = DT;
		
  // We create an access to represent "live on entry", for things like
  // arguments or users of globals. We do not actually insert it in to
  // the IR.
  BasicBlock &StartingPoint = F.getEntryBlock();
  LiveOnEntryDef = new MemoryDef(nullptr, nullptr, &StartingPoint, nextID++);
		
  // We temporarily maintain lists of memory accesses per-block,
  // trading time for memory. We could just look up the memory access
  // for every possible instruction in the stream.
  SmallPtrSet<BasicBlock *, 32> DefiningBlocks;
		
  for (auto &B : F) {
	  AccessListType *Accesses = nullptr;
	  for (auto &I : B) {
		  MemoryAccess *MA = createNewAccess(&I, true);
		  if (!MA)
			  continue;
		  if (isa<MemoryDef>(MA))
			  DefiningBlocks.insert(&B);
		  if (!Accesses)
			  Accesses = getOrCreateAccessList(&B).get();
		  Accesses->push_back(MA);
	  }
  }
		
  // Determine where our MemoryPhi's should go
  IDFCalculator IDFs(*DT);
  IDFs.setDefiningBlocks(DefiningBlocks);
  SmallVector<BasicBlock *, 32> IDFBlocks;
  IDFs.calculate(IDFBlocks);
		
  // Now place MemoryPhi nodes.
  for (auto &BB : IDFBlocks) {
	  // Insert phi node
	  auto &Accesses = getOrCreateAccessList(BB);
	  MemoryPhi *Phi = new MemoryPhi(
									 BB, (unsigned int)std::distance(pred_begin(BB), pred_end(BB)), nextID++);
	  InstructionToMemoryAccess.insert(std::make_pair(BB, Phi));
	  // Phi's always are placed at the front of the block.
	  Accesses->push_front(Phi);
  }
		
  // Now do regular SSA renaming on the MemoryDef/MemoryUse.
  SmallPtrSet<BasicBlock *, 16> Visited;
  renamePass(DT->getRootNode(), LiveOnEntryDef, Visited, Walker);
		
  // Now optimize the MemoryUse's defining access to point to the nearest
  // dominating clobbering def.
  // This ensures that MemoryUse's that are killed by the same store are users
  // of that store.
  for (auto DomNode : depth_first(DT)) {
	  BasicBlock *BB = DomNode->getBlock();
	  auto AI = PerBlockAccesses.find(BB);
	  if (AI == PerBlockAccesses.end())
		  continue;
	  auto &Accesses = AI->second;
	  for (auto &MA : *Accesses) {
		  if (MemoryUse *MU = dyn_cast<MemoryUse>(&MA)) {
			  auto RealVal = Walker->getClobberingMemoryAccess(MU->getMemoryInst());
			  MU->setDefiningAccess(RealVal);
		  }
	  }
  }
		
  // Mark the uses in unreachable blocks as live on entry, so that they go
  // somewhere.
  for (auto &BB : F)
	  if (!Visited.count(&BB))
		  markUnreachableAsLiveOnEntry(&BB);
		
  builtAlready = true;
  return Walker;
	}
	
	static MemoryAccess *getDefiningAccess(MemoryAccess *MA) {
  if (isa<MemoryUse>(MA) || isa<MemoryDef>(MA))
	  return MA->getDefiningAccess();
  else
	  return nullptr;
	}
	static void setDefiningAccess(MemoryAccess *Of, MemoryAccess *To) {
  if (isa<MemoryUse>(Of) || isa<MemoryDef>(Of))
	  Of->setDefiningAccess(To);
	}
	
	/// \brief Properly remove \p MA from all of MemorySSA's lookup tables.
	///
	/// Because of the way the intrusive list and use lists work, it is important to
	/// do removal in the right order.
	void MemorySSA::removeFromLookups(MemoryAccess *MA) {
  assert(MA->user_empty() &&
		 "Trying to remove memory access that still has uses");
  setDefiningAccess(MA, nullptr);
  // Invalidate our walker's cache if necessary
  if (!isa<MemoryUse>(MA))
	  Walker->invalidateInfo(MA);
  // The call below to erase will destroy MA, so we can't change the order we
  // are doing things here
  Instruction *MemoryInst = MA->getMemoryInst();
  if (MemoryInst)
	  InstructionToMemoryAccess.erase(MemoryInst);
  auto &Accesses = PerBlockAccesses.find(MA->getBlock())->second;
  Accesses->erase(MA);
  if (Accesses->empty()) {
	  PerBlockAccesses.erase(MA->getBlock());
  }
	}
	
	/// \brief Helper function to create new memory accesses
	MemoryAccess *MemorySSA::createNewAccess(Instruction *I, bool ignoreNonMemory) {
  // There is no easy way to assert that you are replacing it with a memory
  // access, and this call will assert it for us
  AliasAnalysis::ModRefResult ModRef = AA->getModRefInfo(I);
  bool def = false, use = false;
  if (ModRef & AliasAnalysis::Mod)
	  def = true;
  if (ModRef & AliasAnalysis::Ref)
	  use = true;
		
  // It's possible for an instruction to not modify memory at all. During
  // construction, we ignore them.
  if (ignoreNonMemory && !def && !use)
	  return nullptr;
		
  assert((def || use) &&
		 "Trying to create a memory access with a non-memory instruction");
		
  if (def) {
	  MemoryDef *MD = new MemoryDef(nullptr, I, I->getParent(), nextID++);
	  InstructionToMemoryAccess.insert(std::make_pair(I, MD));
	  return MD;
  } else if (use) {
	  MemoryUse *MU = new MemoryUse(nullptr, I, I->getParent());
	  InstructionToMemoryAccess.insert(std::make_pair(I, MU));
	  return MU;
  }
		
  llvm_unreachable("Not a memory instruction!");
	}
	
	MemoryAccess *MemorySSA::findDominatingDef(BasicBlock *UseBlock,
											   enum InsertionPlace Where) {
  // Handle the initial case
  if (Where == Beginning)
	  // The only thing that could define us at the beginning is a phi node
	  if (MemoryAccess *Phi = getMemoryAccess(UseBlock))
		  return Phi;
		
  DomTreeNode *CurrNode = DT->getNode(UseBlock);
  // Need to be defined by our dominator
  if (Where == Beginning)
	  CurrNode = CurrNode->getIDom();
  Where = End;
  while (CurrNode) {
	  auto It = PerBlockAccesses.find(CurrNode->getBlock());
	  if (It != PerBlockAccesses.end()) {
		  auto &Accesses = It->second;
		  for (auto RAI = Accesses->rbegin(), RAE = Accesses->rend(); RAI != RAE;
			   ++RAI) {
			  if (isa<MemoryDef>(*RAI) || isa<MemoryPhi>(*RAI))
				  return &*RAI;
		  }
	  }
	  CurrNode = CurrNode->getIDom();
  }
  return LiveOnEntryDef;
	}
	
	MemoryAccess *MemorySSA::addNewMemoryUse(Instruction *Use,
											 enum InsertionPlace Where) {
  BasicBlock *UseBlock = Use->getParent();
  MemoryAccess *DefiningDef = findDominatingDef(UseBlock, Where);
  auto &Accesses = getOrCreateAccessList(UseBlock);
  MemoryAccess *MA = createNewAccess(Use);
		
  // Set starting point, then optimize to get correct answer.
  MA->setDefiningAccess(DefiningDef);
  auto RealVal = Walker->getClobberingMemoryAccess(MA->getMemoryInst());
  MA->setDefiningAccess(RealVal);
		
  // Easy case
  if (Where == Beginning) {
	  auto AI = Accesses->begin();
	  while (isa<MemoryPhi>(AI))
		  ++AI;
	  Accesses->insert(AI, MA);
  } else {
	  Accesses->push_back(MA);
  }
  return MA;
	}
	
	MemoryAccess *MemorySSA::replaceMemoryAccessWithNewAccess(
															  MemoryAccess *Replacee, Instruction *Replacer, enum InsertionPlace Where) {
  BasicBlock *ReplacerBlock = Replacer->getParent();
		
  auto &Accesses = getOrCreateAccessList(ReplacerBlock);
  if (Where == Beginning) {
	  // Access must go after the first phi
	  auto AI = Accesses->begin();
	  while (AI != Accesses->end()) {
		  if (!isa<MemoryPhi>(AI))
			  break;
		  ++AI;
	  }
	  return replaceMemoryAccessWithNewAccess(Replacee, Replacer, AI);
  } else {
	  return replaceMemoryAccessWithNewAccess(Replacee, Replacer,
											  Accesses->end());
  }
	}
	
	MemoryAccess *MemorySSA::replaceMemoryAccessWithNewAccess(
															  MemoryAccess *Replacee, Instruction *Replacer,
															  const AccessListType::iterator &Where) {
		
  BasicBlock *ReplacerBlock = Replacer->getParent();
  MemoryAccess *MA = nullptr;
  MemoryAccess *DefiningAccess = getDefiningAccess(Replacee);
		
  // Handle the case we are replacing a phi node, in which case, we don't kill
  // the phi node
  if (DefiningAccess == nullptr) {
	  assert(isa<MemoryPhi>(Replacee) &&
			 "Should have been a phi node if we can't get a defining access");
	  assert(DT->dominates(Replacee->getBlock(), ReplacerBlock) &&
			 "Need to reuse PHI for defining access, but it will not dominate "
			 "replacing instruction");
	  DefiningAccess = Replacee;
  }
		
  MA = createNewAccess(Replacer);
  MA->setDefiningAccess(DefiningAccess);
  auto It = PerBlockAccesses.find(ReplacerBlock);
  assert(It != PerBlockAccesses.end() &&
		 "Can't use iterator insertion for brand new block");
  auto &Accesses = It->second;
  Accesses->insert(Where, MA);
  replaceMemoryAccess(Replacee, MA);
  return MA;
	}
	
	/// \brief Returns true if \p Replacer dominates \p Replacee .
	bool MemorySSA::dominatesUse(const MemoryAccess *Replacer,
								 const MemoryAccess *Replacee) const {
  if (isa<MemoryUse>(Replacee) || isa<MemoryDef>(Replacee))
	  return DT->dominates(Replacer->getBlock(), Replacee->getBlock());
  const MemoryPhi *MP = cast<MemoryPhi>(Replacee);
  // For a phi node, the use occurs in the predecessor block of the phi node.
  // Since we may occur multiple times in the phi node, we have to check each
  // operand to ensure Replacer dominates each operand where Replacee occurs.
  for (const auto &Arg : MP->operands())
	  if (Arg.second == Replacee)
		  if (!DT->dominates(Replacer->getBlock(), Arg.first))
			  return false;
  return true;
	}
	
	/// \brief Replace all occurrences of \p Replacee with \p Replacer in a PHI
	/// node.
	/// \return true if we replaced all operands of the phi node.
	bool MemorySSA::replaceAllOccurrences(MemoryPhi *P, MemoryAccess *Replacee,
										  MemoryAccess *Replacer) {
  bool ReplacedAllValues = true;
  for (unsigned i = 0, e = P->getNumIncomingValues(); i != e; ++i) {
	  if (P->getIncomingValue(i) == Replacee)
		  P->setIncomingValue(i, Replacer);
	  else
		  ReplacedAllValues = false;
  }
  return ReplacedAllValues;
	}
	
	void MemorySSA::replaceMemoryAccess(MemoryAccess *Replacee,
										MemoryAccess *Replacer) {
		
  // If we don't replace all phi node entries, we can't remove it.
  bool replacedAllPhiEntries = true;
  // If we are replacing a phi node, we may still actually use it, since we
  // may now be defined in terms of it.
  bool usedByReplacee = getDefiningAccess(Replacer) == Replacee;
		
  // Just to note: We can replace the live on entry def, unlike removing it, so
  // we don't assert here, but it's almost always a bug, unless you are
  // inserting a load/store in a block that dominates the rest of the program.
  for (auto U : Replacee->users()) {
	  if (U == Replacer)
		  continue;
	  assert(dominatesUse(Replacer, Replacee) &&
			 "Definitions will not dominate uses in replacement!");
	  if (MemoryPhi *MP = dyn_cast<MemoryPhi>(U)) {
		  if (replaceAllOccurrences(MP, Replacee, Replacer))
			  replacedAllPhiEntries = true;
	  } else {
		  U->setDefiningAccess(Replacer);
	  }
  }
  // Kill our dead replacee if it's really dead
  if (replacedAllPhiEntries && !usedByReplacee) {
	  removeFromLookups(Replacee);
  }
	}
	
#ifndef NDEBUG
	/// \brief Returns true if a phi is defined by the same value on all edges
	static bool onlySingleValue(MemoryPhi *MP) {
  MemoryAccess *MA = nullptr;
		
  for (const auto &Arg : MP->operands()) {
	  if (!MA)
		  MA = Arg.second;
	  else if (MA != Arg.second)
		  return false;
  }
  return true;
	}
#endif
	
	void MemorySSA::removeMemoryAccess(MemoryAccess *MA) {
  assert(MA != LiveOnEntryDef && "Trying to remove the live on entry def");
  // We can only delete phi nodes if they are use empty
  if (MemoryPhi *MP = dyn_cast<MemoryPhi>(MA)) {
	  // This code only used in assert builds
	  (void)MP;
	  assert(MP->user_empty() && "We can't delete memory phis that still have "
			 "uses, we don't know where the uses should "
			 "repoint to!");
	  assert((MP->user_empty() || onlySingleValue(MP)) &&
			 "This phi still points to multiple values, "
			 "which means it is still needed");
  } else {
	  MemoryAccess *DefiningAccess = getDefiningAccess(MA);
	  // Re-point the uses at our defining access
	  for (auto U : MA->users()) {
		  assert(dominatesUse(DefiningAccess, U) &&
				 "Definitions will not dominate uses in removal!");
		  if (MemoryPhi *MP = dyn_cast<MemoryPhi>(U)) {
			  replaceAllOccurrences(MP, MA, DefiningAccess);
		  } else {
			  U->setDefiningAccess(DefiningAccess);
		  }
	  }
  }
		
  // The call below to erase will destroy MA, so we can't change the order we
  // are doing things here
  removeFromLookups(MA);
	}
	
	void MemorySSA::print(raw_ostream &OS) const {
  MemorySSAAnnotatedWriter Writer(this);
  F.print(OS, &Writer);
	}
	
	void MemorySSA::dump() const {
  MemorySSAAnnotatedWriter Writer(this);
  F.print(dbgs(), &Writer);
	}
	
	/// \brief Verify the domination properties of MemorySSA by checking that each
	/// definition dominates all of its uses.
	void MemorySSA::verifyDomination(Function &F) {
  for (auto &B : F) {
	  // Phi nodes are attached to basic blocks
	  MemoryAccess *MA = getMemoryAccess(&B);
	  if (MA) {
		  MemoryPhi *MP = cast<MemoryPhi>(MA);
		  for (const auto &U : MP->users()) {
			  BasicBlock *UseBlock;
			  // Phi operands are used on edges, we simulate the right domination by
			  // acting as if the use occurred at the end of the predecessor block.
			  if (MemoryPhi *P = dyn_cast<MemoryPhi>(U)) {
				  for (const auto &Arg : P->operands()) {
					  if (Arg.second == MP) {
						  UseBlock = Arg.first;
						  break;
					  }
				  }
			  } else {
				  UseBlock = U->getBlock();
			  }
			  assert(DT->dominates(MP->getBlock(), UseBlock) &&
					 "Memory PHI does not dominate it's uses");
		  }
	  }
	  for (auto &I : B) {
		  MA = getMemoryAccess(&I);
		  if (MA) {
			  if (MemoryDef *MD = dyn_cast<MemoryDef>(MA))
				  for (const auto &U : MD->users()) {
					  BasicBlock *UseBlock;
					  // Things are allowed to flow to phi nodes over their predecessor
					  // edge.
					  if (MemoryPhi *P = dyn_cast<MemoryPhi>(U)) {
						  for (const auto &Arg : P->operands()) {
							  if (Arg.second == MD) {
								  UseBlock = Arg.first;
								  break;
							  }
						  }
					  } else {
						  UseBlock = U->getBlock();
					  }
					  assert(DT->dominates(MD->getBlock(), UseBlock) &&
							 "Memory Def does not dominate it's uses");
				  }
		  }
	  }
  }
	}
	
	/// \brief Verify the def-use lists in MemorySSA, by verifying that \p Use
	/// appears in the use list of \p Def.
	void MemorySSA::verifyUseInDefs(MemoryAccess *Def, MemoryAccess *Use) {
  // The live on entry use may cause us to get a NULL def here
  if (Def == nullptr) {
	  assert(isLiveOnEntryDef(Use) &&
			 "Null def but use not point to live on entry def");
	  return;
  }
  assert(Def->hasUse(Use) && "Did not find use in def's use list");
	}
	
	/// \brief Verify the immediate use information, by walking all the memory
	/// accesses and verifying that, for each use, it appears in the
	/// appropriate def's use list
	void MemorySSA::verifyDefUses(Function &F) {
  for (auto &B : F) {
	  // Phi nodes are attached to basic blocks
	  MemoryAccess *MA = getMemoryAccess(&B);
	  if (MA) {
		  assert(isa<MemoryPhi>(MA) &&
				 "Something other than phi node on basic block");
		  MemoryPhi *MP = cast<MemoryPhi>(MA);
		  for (unsigned i = 0, e = MP->getNumIncomingValues(); i != e; ++i)
			  verifyUseInDefs(MP->getIncomingValue(i), MP);
	  }
	  for (auto &I : B) {
		  MA = getMemoryAccess(&I);
		  if (MA) {
			  if (MemoryPhi *MP = dyn_cast<MemoryPhi>(MA)) {
				  for (unsigned i = 0, e = MP->getNumIncomingValues(); i != e; ++i)
					  verifyUseInDefs(MP->getIncomingValue(i), MP);
			  } else {
				  verifyUseInDefs(MA->getDefiningAccess(), MA);
			  }
		  }
	  }
  }
	}
	
	MemoryAccess *MemorySSA::getMemoryAccess(const Value *I) const {
  return InstructionToMemoryAccess.lookup(I);
	}
	
	bool MemorySSA::locallyDominates(const MemoryAccess *Dominator,
									 const MemoryAccess *Dominatee) const {
		
  assert((Dominator->getBlock() == Dominatee->getBlock()) &&
		 "Asking for local domination when accesses are in different blocks!");
  // Get the access list for the block
  const auto *AccessList = getBlockAccesses(Dominator->getBlock());
  AccessListType::const_reverse_iterator It(Dominator);
		
  // If we hit the beginning of the access list before we hit dominatee, we must
  // dominate it
  while (It != AccessList->rend()) {
	  if (&*It == Dominatee)
		  return false;
	  ++It;
  }
  return true;
	}
	
	void MemoryDef::print(raw_ostream &OS) const {
  MemoryAccess *UO = getDefiningAccess();
		
  OS << getID() << " = "
		<< "MemoryDef(";
  if (UO && UO->getID() != 0)
	  OS << UO->getID();
  else
	  OS << "liveOnEntry";
  OS << ")";
	}
	
	void MemoryPhi::print(raw_ostream &OS) const {
  OS << getID() << " = "
		<< "MemoryPhi(";
  for (unsigned int i = 0, e = getNumIncomingValues(); i != e; ++i) {
	  BasicBlock *BB = getIncomingBlock(i);
	  MemoryAccess *MA = getIncomingValue(i);
	  OS << "{";
	  if (BB->hasName())
		  OS << BB->getName();
	  else
		  BB->printAsOperand(OS, false);
	  OS << ",";
	  assert((isa<MemoryDef>(MA) || isa<MemoryPhi>(MA)) &&
			 "Phi node should have referred to def or another phi");
	  if (MA->getID() != 0)
		  OS << MA->getID();
	  else
		  OS << "liveOnEntry";
	  OS << "}";
	  if (i + 1 < e)
		  OS << ",";
  }
  OS << ")";
	}
	
	MemoryAccess::~MemoryAccess() {}
	
	void MemoryUse::print(raw_ostream &OS) const {
  MemoryAccess *UO = getDefiningAccess();
  OS << "MemoryUse(";
  if (UO && UO->getID() != 0)
	  OS << UO->getID();
  else
	  OS << "liveOnEntry";
  OS << ")";
	}
	
	void MemoryAccess::dump() const {
  print(dbgs());
  dbgs() << "\n";
	}
	
	char MemorySSAPrinterPass::ID = 0;
	
	MemorySSAPrinterPass::MemorySSAPrinterPass() : FunctionPass(ID) {
  initializeMemorySSAPrinterPassPass(*PassRegistry::getPassRegistry());
	}
	
	void MemorySSAPrinterPass::releaseMemory() {
  delete MSSA;
  delete Walker;
	}
	
	void MemorySSAPrinterPass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.setPreservesAll();
  AU.addRequiredTransitive<AliasAnalysis>();
  AU.addRequired<DominatorTreeWrapperPass>();
	}
	
	bool MemorySSAPrinterPass::doInitialization(Module &M) {
		
  VerifyMemorySSA =
		M.getContext()
		.template getOption<bool, MemorySSAPrinterPass,
		&MemorySSAPrinterPass::VerifyMemorySSA>();
  return false;
	}
	
	void MemorySSAPrinterPass::registerOptions() {
  OptionRegistry::registerOption<bool, MemorySSAPrinterPass,
		&MemorySSAPrinterPass::VerifyMemorySSA>(
												"verify-memoryssa", "Run the Memory SSA verifier", false);
	}
	
	void MemorySSAPrinterPass::print(raw_ostream &OS, const Module *M) const {
  MSSA->print(OS);
	}
	
	bool MemorySSAPrinterPass::runOnFunction(Function &F) {
  this->F = &F;
  MSSA = new MemorySSA(F);
  AliasAnalysis *AA = &getAnalysis<AliasAnalysis>();
  DominatorTree *DT = &getAnalysis<DominatorTreeWrapperPass>().getDomTree();
  Walker = MSSA->buildMemorySSA(AA, DT);
		
  if (VerifyMemorySSA) {
	  MSSA->verifyDefUses(F);
	  MSSA->verifyDomination(F);
  }
		
  return false;
	}
	
	char MemorySSALazy::ID = 0;
	
	MemorySSALazy::MemorySSALazy() : FunctionPass(ID) {
  initializeMemorySSALazyPass(*PassRegistry::getPassRegistry());
	}
	
	void MemorySSALazy::releaseMemory() { delete MSSA; }
	
	bool MemorySSALazy::runOnFunction(Function &F) {
  MSSA = new MemorySSA(F);
  return false;
	}
	
	MemorySSAWalker::MemorySSAWalker(MemorySSA *M) : MSSA(M) {}
	
	CachingMemorySSAWalker::CachingMemorySSAWalker(MemorySSA *M, AliasAnalysis *A,
												   DominatorTree *D)
	: MemorySSAWalker(M), AA(A), DT(D) {}
	
	CachingMemorySSAWalker::~CachingMemorySSAWalker() {
  CachedUpwardsClobberingAccess.clear();
  CachedUpwardsClobberingCall.clear();
	}
	
	struct CachingMemorySSAWalker::UpwardsMemoryQuery {
  // True if we saw a phi whose predecessor was a backedge
  bool SawBackedgePhi;
  // True if our original query started off as a call
  bool isCall;
  // The pointer location we started the query with. This will be
  // empty if isCall is true.
  MemoryLocation StartingLoc;
  // This is the instruction we were querying about.
  const Instruction *Inst;
  // Set of visited Instructions for this query.
  DenseSet<MemoryAccessPair> Visited;
  // Set of visited call accesses for this query This is separated out because
  // you can always cache and lookup the result of call queries (IE when
  // isCall == true) for every call in the chain. The calls have no AA
  // location associated with them with them, and thus, no context dependence.
  SmallPtrSet<const MemoryAccess *, 32> VisitedCalls;
  // The MemoryAccess we actually got called with, used to test local domination
  const MemoryAccess *OriginalAccess;
  // The Datalayout for the module we started in
  const DataLayout *DL;
	};
	
	void CachingMemorySSAWalker::doCacheRemove(const MemoryAccess *M,
											   const UpwardsMemoryQuery &Q,
											   const MemoryLocation &Loc) {
  if (Q.isCall)
	  CachedUpwardsClobberingCall.erase(M);
  else
	  CachedUpwardsClobberingAccess.erase({M, Loc});
	}
	
	void CachingMemorySSAWalker::doCacheInsert(const MemoryAccess *M,
											   MemoryAccess *Result,
											   const UpwardsMemoryQuery &Q,
											   const MemoryLocation &Loc) {
  ++NumClobberCacheInserts;
  if (Q.isCall)
	  CachedUpwardsClobberingCall[M] = Result;
  else
	  CachedUpwardsClobberingAccess[{M, Loc}] = Result;
	}
	
	MemoryAccess *CachingMemorySSAWalker::doCacheLookup(const MemoryAccess *M,
														const UpwardsMemoryQuery &Q,
														const MemoryLocation &Loc) {
  ++NumClobberCacheLookups;
  MemoryAccess *Result = nullptr;
		
  if (Q.isCall)
	  Result = CachedUpwardsClobberingCall.lookup(M);
  else
	  Result = CachedUpwardsClobberingAccess.lookup({M, Loc});
		
  if (Result) {
	  ++NumClobberCacheHits;
	  return Result;
  }
  return nullptr;
	}
	
	/// \brief Return true if \p QueryInst could possibly have a Mod result with \p
	/// DefInst.
	static bool possiblyAffectedBy(const Instruction *QueryInst,
								   const Instruction *DefInst) {
  if (isa<LoadInst>(DefInst) && isa<LoadInst>(QueryInst)) {
	  const LoadInst *DefLI = cast<LoadInst>(DefInst);
	  const LoadInst *QueryLI = cast<LoadInst>(QueryInst);
	  // A non-volatile load can't be clobbered by a volatile one unless the
	  // volatile one is ordered.
	  if (!QueryLI->isVolatile() && DefLI->isVolatile())
		  return DefLI->getOrdering() > Unordered;
  }
  return true;
	}
	
	bool CachingMemorySSAWalker::instructionClobbersQuery(
														  const MemoryDef *MD, struct UpwardsMemoryQuery &Q,
														  const MemoryLocation &Loc) const {
  Instruction *DefMemoryInst = MD->getMemoryInst();
  assert(DefMemoryInst && "Defining instruction not actually an instruction");
		
  if (!Q.isCall) {
	  // Okay, well, see if it's a volatile load vs non-volatile load
	  // situation.
	  if (possiblyAffectedBy(Q.Inst, DefMemoryInst))
		  // Check whether our memory location is modified by this instruction
		  if (AA->getModRefInfo(DefMemoryInst, Loc) & AliasAnalysis::Mod)
			  return true;
  } else {
	  // If this is a call, try then mark it for caching
	  if (ImmutableCallSite(DefMemoryInst)) {
		  Q.VisitedCalls.insert(MD);
	  }
	  if (AA->getModRefInfo(DefMemoryInst, ImmutableCallSite(Q.Inst)) !=
		  AliasAnalysis::NoModRef)
		  return true;
  }
  return false;
	}
	
	MemoryAccessPair CachingMemorySSAWalker::UpwardsDFSWalk(
															MemoryAccess *StartingAccess, const MemoryLocation &Loc,
															UpwardsMemoryQuery &Q, bool FollowingBackedge) {
  MemoryAccess *ModifyingAccess = nullptr;
		
  auto DFI = df_begin(StartingAccess);
  for (auto DFE = df_end(StartingAccess); DFI != DFE;) {
	  MemoryAccess *CurrAccess = *DFI;
	  if (MSSA->isLiveOnEntryDef(CurrAccess))
		  return {CurrAccess, Loc};
	  if (auto CacheResult = doCacheLookup(CurrAccess, Q, Loc)) {
		  return {CacheResult, Loc};
	  }
	  // If this is a MemoryDef, check whether it clobbers our current query.
	  if (MemoryDef *MD = dyn_cast<MemoryDef>(CurrAccess)) {
		  // If we hit the top, stop following this path
		  // While we can do lookups, we can't sanely do inserts here unless we
		  // were to track every thing we saw along the way, since we don't
		  // know where we will stop.
		  if (instructionClobbersQuery(MD, Q, Loc)) {
			  ModifyingAccess = CurrAccess;
			  break;
		  }
	  }
	  // We need to know whether it is a phi so we can track backedges.
	  // Otherwise, walk all upward defs.
	  bool IsPhi = isa<MemoryPhi>(CurrAccess);
	  // Recurse on PHI nodes, since we need to change locations.
	  // TODO: Allow graphtraits on pairs, which would turn this whole function
	  // into a normal single depth first walk.
	  if (IsPhi) {
		  MemoryAccess *FirstDef = nullptr;
		  DFI = DFI.skipChildren();
		  const MemoryAccessPair PHIPair(CurrAccess, Loc);
		  if (Q.Visited.count(PHIPair))
			  return PHIPair;
		  for (auto MPI = upward_defs_begin(PHIPair), MPE = upward_defs_end();
			   MPI != MPE; ++MPI) {
			  bool Backedge = false;
			  // Don't follow this path again if we've followed it once
			  if (!Q.Visited.insert(*MPI).second)
				  continue;
			  if (IsPhi && !FollowingBackedge &&
				  DT->dominates(CurrAccess->getBlock(), MPI.getPhiArgBlock()))
				  Backedge = true;
			  MemoryAccessPair CurrentPair =
			  UpwardsDFSWalk(MPI->first, MPI->second, Q, Backedge);
			  // All the phi arguments should reach the same point if we can bypass
			  // this phi.  The alternative is that they hit this phi node, which
			  // means we can skip this argument.
			  if (FirstDef && (CurrentPair.first != PHIPair.first &&
							   FirstDef != CurrentPair.first)) {
				  ModifyingAccess = CurrAccess;
				  break;
			  } else if (!FirstDef) {
				  FirstDef = CurrentPair.first;
			  }
		  }
	  } else {
		  // You can't call skipchildren and also increment the iterator
		  ++DFI;
	  }
  }
  if (!ModifyingAccess)
	  return {MSSA->getLiveOnEntryDef(), Q.StartingLoc};
  const BasicBlock *OriginalBlock = Q.OriginalAccess->getBlock();
  unsigned N = DFI.getPathLength();
  MemoryAccess *FinalAccess = ModifyingAccess;
		
  for (; N != 0; --N) {
	  ModifyingAccess = DFI.getPath(N - 1);
	  BasicBlock *CurrBlock = ModifyingAccess->getBlock();
	  if (!FollowingBackedge)
		  doCacheInsert(ModifyingAccess, FinalAccess, Q, Loc);
	  if (DT->dominates(CurrBlock, OriginalBlock) &&
		  (CurrBlock != OriginalBlock || !FollowingBackedge ||
		   MSSA->locallyDominates(ModifyingAccess, Q.OriginalAccess)))
		  break;
  }
  // Cache everything else on the way back
  for (; N != 0; --N) {
	  MemoryAccess *CacheAccess = DFI.getPath(N - 1);
	  doCacheInsert(CacheAccess, ModifyingAccess, Q, Loc);
  }
  assert(Q.Visited.size() < 1000 && "Visited too much");
		
  return {ModifyingAccess, Loc};
	}
	
	/// \brief Perform a BFS walking, starting at \p StartingAccess, and going
	/// upwards (IE through defining accesses) until we reach something that
	/// Mod's StartingAccess's memory location.
	///
	/// \p Prev is filled in with the immediate predecessor of each node when
	/// walking, so that the path we took from EndingAccess to StartingAccess can be
	/// traced by walking through Prev.
	///
	/// TODO: It would be really nice to have a bfs iterator that we can use to do
	/// upwards and downwards walks.  This would require making iterators for the
	/// memory access types, graphtraits, making bfs_ext iterators.
	std::pair<MemoryAccess *, MemoryLocation>
	CachingMemorySSAWalker::UpwardsBFSWalkAccess(MemoryAccess *StartingAccess,
												 PathMap &Prev,
												 UpwardsMemoryQuery &Q) {
  std::queue<MemoryAccessPair> Worklist;
  Q.Visited.insert({StartingAccess, Q.StartingLoc});
  Worklist.emplace(StartingAccess, Q.StartingLoc);
  MemoryAccess *ModifyingAccess = nullptr;
  unsigned N = 0;
  Q.SawBackedgePhi = false;
		
  MemoryLocation Loc;
  while (!Worklist.empty()) {
	  N++;
	  assert(N < 10000 && "In the walk for too long");
	  const MemoryAccessPair Pair = Worklist.front();
	  MemoryAccess *CurrAccess = Pair.first;
	  Loc = Pair.second;
	  Worklist.pop();
	  if (MSSA->isLiveOnEntryDef(CurrAccess))
		  continue;
	  if (auto CacheResult = doCacheLookup(CurrAccess, Q, Loc)) {
		  if (Q.Visited.insert({CacheResult, Loc}).second)
			  Prev[{CacheResult, Loc}] = {CurrAccess, Loc};
		  return {CacheResult, Loc};
	  }
	  
	  // If this is a MemoryDef, check whether it clobbers our current query.
	  if (MemoryDef *MD = dyn_cast<MemoryDef>(CurrAccess)) {
		  // If we hit the top, stop following this path
		  // While we can do lookups, we can't sanely do inserts here unless we
		  // were to track every thing we saw along the way, since we don't
		  // know where we will stop.
		  if (instructionClobbersQuery(MD, Q, Loc)) {
			  ModifyingAccess = CurrAccess;
			  break;
		  }
	  }
	  // We need to know whether it is a phi so we can track backedges.
	  // Otherwise, walk all upward defs.
	  bool IsPhi = isa<MemoryPhi>(CurrAccess);
	  for (auto MPI = upward_defs_begin(Pair), MPE = upward_defs_end();
		   MPI != MPE; ++MPI) {
		  if (IsPhi && !Q.SawBackedgePhi &&
			  DT->dominates(CurrAccess->getBlock(), MPI.getPhiArgBlock()))
			  Q.SawBackedgePhi = true;
		  // We may have already visited this argument along another path
		  if (!Q.Visited.insert(*MPI).second)
			  continue;
		  
		  assert(Prev.count(*MPI) == 0 &&
				 "This part of the map should not  already be filled in!");
		  
		  // Finally, enqueue the argument and new pointer, and set the map to
		  // say we got here from the phi and the old pointer.
		  Prev[*MPI] = Pair;
		  
		  Worklist.emplace(*MPI);
	  }
  }
		
  // If we emptied the worklist, it means every path to the beginning of the
  // function had nothing that MOD'd our query.  This means we should return the
  // live on entry def.  Note that CurrAccess will not always be the
  // liveOnEntryDef at his point. If, for example, the last path we followed led
  // into a cycle, it will be something else.
  if (!ModifyingAccess && Worklist.empty())
	  return {MSSA->getLiveOnEntryDef(), Q.StartingLoc};
		
  return {ModifyingAccess, Loc};
	}
	
	/// \brief Walk the use-def chains starting at \p MA and find
	/// the MemoryAccess that actually clobbers Loc.
	///
	/// \returns a pair of clobbering memory access and whether we hit a cyclic phi
	/// node.
	MemoryAccess *CachingMemorySSAWalker::getClobberingMemoryAccess(
																	MemoryAccess *StartingAccess, struct UpwardsMemoryQuery &Q) {
  PathMap Prev;
  auto CurrAccessPair = UpwardsBFSWalkAccess(StartingAccess, Prev, Q);
  // Either we will have found something that conflicts with us, or we will have
  // hit the liveOnEntry. Check for liveOnEntry.
  if (MSSA->isLiveOnEntryDef(CurrAccessPair.first))
	  return CurrAccessPair.first;
  // Now find the thing that dominates us from the path we found to the
  // clobbering access.
  MemoryAccessPair FinalAccessPair =
		findDominatingAccess(StartingAccess, CurrAccessPair, Prev, Q);
  MemoryAccess *FinalAccess = FinalAccessPair.first;
  assert(FinalAccessPair.first &&
		 "Should have found something that dominated our original access");
  // Everything along the rest of the path now terminates at CurrAccess
  // TODO
  // 1. We could cache the rest of the prev map as partial cache info and
  // restart the BFS walk from it if and when we need to
  // 2. We also know that anything in the Prev map with the same Loc that is
  // dominated by FinalAccess, also terminates in FinalAccess (by the definition
  // of the domination). We could cache these as well.
		
  // This just avoids doing a cache insert of the same thing twice, in the case
  // that our walk terminated in something that dominated our original access.
  // In that case, we would insert both here and in the loop below.
  if (FinalAccess != CurrAccessPair.first)
	  doCacheInsert(CurrAccessPair.first, CurrAccessPair.first, Q,
					CurrAccessPair.second);
		
  unsigned N = 0;
  MemoryAccess *CacheAccess = FinalAccess;
  MemoryLocation CacheLoc = FinalAccessPair.second;
  while (CacheAccess) {
	  doCacheInsert(CacheAccess, FinalAccess, Q, CacheLoc);
	  const auto &PrevResult = Prev.lookup({CacheAccess, CacheLoc});
	  CacheAccess = PrevResult.first;
	  CacheLoc = PrevResult.second;
	  ++N;
	  assert(N < 10000 && "In the second loop too many times");
  }
		
  return FinalAccess;
	}
	
	MemoryAccessPair CachingMemorySSAWalker::findDominatingAccess(
																  const MemoryAccess *StartingAccess, const MemoryAccessPair &FinalAccessPair,
																  const PathMap &Path, const struct UpwardsMemoryQuery &Q) const {
  // This means walking the prev pointers backwards to figure
  // out how we go to this clobber, stopping when we find something that
  // dominates the original access.
  // If we saw a phi node with a backedge, the thing that we found in our block
  // may in fact be below us, in which case, we need to check local domination
  // if the found access is in the same block as the starting access.
		
  // Since this code may be a little confusing, here is what is happening:
  // First we extract the block of the original access that the user queried
  // about, I.E. the access for the instruction they passed to
  // getClobberingAccess.
  // This may or may *not* be the same as StartingAccess (for a MemoryUse, the
  // StartingAccess might be the RHS def, depending on which query function was
  // used).
  // However, we know that StartingAccess dominates our OriginalAccess, so
  // either we should find something "better", or we should get back to
  // StartingAccess.  The null check below is just to make sure the loop
  // terminates. We assert that it does not happen.
		
  const BasicBlock *OriginalBlock = Q.OriginalAccess->getBlock();
  MemoryAccess *FinalAccess = FinalAccessPair.first;
  MemoryLocation FinalLoc = FinalAccessPair.second;
  unsigned int N = 0;
  while (FinalAccess && FinalAccess != StartingAccess) {
	  BasicBlock *CurrBlock = FinalAccess->getBlock();
	  if (DT->dominates(CurrBlock, OriginalBlock) &&
		  (CurrBlock != OriginalBlock || !Q.SawBackedgePhi ||
		   MSSA->locallyDominates(FinalAccess, Q.OriginalAccess)))
		  break;
	  
	  const auto &PrevResult = Path.lookup({FinalAccess, FinalLoc});
	  FinalAccess = PrevResult.first;
	  FinalLoc = PrevResult.second;
	  ++N;
	  assert(N < 10000 && "In the loop too many times");
  }
  return {FinalAccess, FinalLoc};
	}
	
	MemoryAccess *
	CachingMemorySSAWalker::getClobberingMemoryAccess(MemoryAccess *StartingAccess,
													  MemoryLocation &Loc) {
  if (isa<MemoryPhi>(StartingAccess))
	  return StartingAccess;
  if (MSSA->isLiveOnEntryDef(StartingAccess))
	  return StartingAccess;
		
  Instruction *I = StartingAccess->getMemoryInst();
		
  struct UpwardsMemoryQuery Q;
  if (isa<FenceInst>(I))
	  return StartingAccess;
		
  Q.OriginalAccess = StartingAccess;
  Q.StartingLoc = Loc;
  Q.Inst = StartingAccess->getMemoryInst();
  Q.isCall = false;
  Q.DL = &Q.Inst->getParent()->getModule()->getDataLayout();
		
  auto CacheResult = doCacheLookup(StartingAccess, Q, Q.StartingLoc);
  if (CacheResult)
	  return CacheResult;
		
  // Unlike the other function, do not walk to the def of a def, because we are
  // handed
  // something we already believe is the clobbering access.
  if (isa<MemoryUse>(StartingAccess))
	  StartingAccess = StartingAccess->getDefiningAccess();
		
  MemoryAccess *FinalAccess = getClobberingMemoryAccess(StartingAccess, Q);
  doCacheInsert(Q.OriginalAccess, FinalAccess, Q, Q.StartingLoc);
  DEBUG(dbgs() << "Starting Memory SSA clobber for " << *I << " is ");
  DEBUG(dbgs() << *StartingAccess << "\n");
  DEBUG(dbgs() << "Final Memory SSA clobber for " << *I << " is ");
  DEBUG(dbgs() << *FinalAccess << "\n");
		
  return FinalAccess;
	}
	
	MemoryAccess *
	CachingMemorySSAWalker::getClobberingMemoryAccess(const Instruction *I) {
		
  MemoryAccess *StartingAccess = MSSA->getMemoryAccess(I);
		
  // There should be no way to lookup an instruction and get a phi as the
  // access, since we only map BB's to PHI's.
  assert(!isa<MemoryPhi>(StartingAccess));
		
  struct UpwardsMemoryQuery Q;
  Q.OriginalAccess = StartingAccess;
		
  // First extract our location, then start walking until it is
  // clobbered
  // For calls, we store the call instruction we started with in
  // Loc.Ptr
  MemoryLocation Loc(I);
  // We can't sanely do anything with a FenceInst, they conservatively
  // clobber all memory, and have no locations to get pointers from to
  // try to disambiguate
  if (isa<FenceInst>(I)) {
	  return StartingAccess;
  } else if (ImmutableCallSite(I)) {
	  Q.isCall = true;
	  Q.Inst = I;
  } else {
	  Q.isCall = false;
	  Q.StartingLoc = MemoryLocation::get(I);
	  Q.Inst = I;
  }
  Q.DL = &Q.Inst->getParent()->getModule()->getDataLayout();
  auto CacheResult = doCacheLookup(StartingAccess, Q, Q.StartingLoc);
  if (CacheResult)
	  return CacheResult;
		
  // Short circuit invariant loads
  if (const LoadInst *LI = dyn_cast<LoadInst>(I))
	  if (LI->getMetadata(LLVMContext::MD_invariant_load) != nullptr) {
		  doCacheInsert(StartingAccess, MSSA->getLiveOnEntryDef(), Q,
						Q.StartingLoc);
		  return MSSA->getLiveOnEntryDef();
	  }
		
  // Start with the thing we already think clobbers this location
  StartingAccess = StartingAccess->getDefiningAccess();
		
  // At this point, StartingAccess may be the live on entry def.
  // If it is, we will not get a better result.
  if (MSSA->isLiveOnEntryDef(StartingAccess))
	  return StartingAccess;
  MemoryAccess *FinalAccess = getClobberingMemoryAccess(StartingAccess, Q);
		
  doCacheInsert(Q.OriginalAccess, FinalAccess, Q, Q.StartingLoc);
  if (Q.isCall) {
	  for (const auto &C : Q.VisitedCalls)
		  doCacheInsert(C, FinalAccess, Q, Q.StartingLoc);
  }
		
  DEBUG(dbgs() << "Starting Memory SSA clobber for " << *I << " is ");
  DEBUG(dbgs() << *StartingAccess << "\n");
  DEBUG(dbgs() << "Final Memory SSA clobber for " << *I << " is ");
  DEBUG(dbgs() << *FinalAccess << "\n");
		
  return FinalAccess;
	}
	
	void CachingMemorySSAWalker::invalidateInfo(MemoryAccess *MA) {
  UpwardsMemoryQuery Q;
  if (!isa<MemoryPhi>(MA)) {
	  Instruction *I = MA->getMemoryInst();
	  if (ImmutableCallSite(I)) {
		  Q.isCall = true;
		  Q.Inst = I;
	  } else {
		  Q.isCall = false;
		  Q.StartingLoc = MemoryLocation::get(I);
		  Q.Inst = I;
	  }
  }
		
  doCacheRemove(MA, Q, Q.StartingLoc);
	}
	
	MemoryAccess *
	DoNothingMemorySSAWalker::getClobberingMemoryAccess(const Instruction *I) {
  MemoryAccess *MA = MSSA->getMemoryAccess(I);
  if (isa<MemoryPhi>(MA))
	  return MA;
  return MA->getDefiningAccess();
	}
	
	MemoryAccess *DoNothingMemorySSAWalker::getClobberingMemoryAccess(
																	  MemoryAccess *StartingAccess, MemoryLocation &) {
  if (isa<MemoryPhi>(StartingAccess))
	  return StartingAccess;
  return StartingAccess->getDefiningAccess();
	}
}
