//===- MemorySSA.h - Build Memory SSA ---------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// \file
// \brief This file exposes an interface to building/using memory SSA to
// walk memory instructions using a use/def graph

// Memory SSA class builds an SSA form that links together memory access
// instructions such loads, stores, atomics and calls.  Additionally, it does a
// trivial form of "heap versioning" Every time the memory state changes in the
// program, we generate a new heap version It generates MemoryDef/Uses/Phis that
// are overlayed on top of the existing instructions

// As a trivial example,
// define i32 @main() #0 {
// entry:
//   %call = call noalias i8* @_Znwm(i64 4) #2
//   %0 = bitcast i8* %call to i32*
//   %call1 = call noalias i8* @_Znwm(i64 4) #2
//   %1 = bitcast i8* %call1 to i32*
//   store i32 5, i32* %0, align 4
//   store i32 7, i32* %1, align 4
//   %2 = load i32* %0, align 4
//   %3 = load i32* %1, align 4
//   %add = add nsw i32 %2, %3
//   ret i32 %add
// }
// Will become
//  define i32 @main() #0 {
// entry:
//   ; 1 = MemoryDef(0)
//   %call = call noalias i8* @_Znwm(i64 4) #3
//   %2 = bitcast i8* %call to i32*
//   ; 2 = MemoryDef(1)
//   %call1 = call noalias i8* @_Znwm(i64 4) #3
//   %4 = bitcast i8* %call1 to i32*
//   ; 3 = MemoryDef(2)
//   store i32 5, i32* %2, align 4
//   ; 4 = MemoryDef(3)
//   store i32 7, i32* %4, align 4
//   ; MemoryUse(4)
//   %7 = load i32* %2, align 4
//   ; MemoryUse(3)
//   %8 = load i32* %4, align 4
//   %add = add nsw i32 %7, %8
//   ret i32 %add
// }
// Given this form, all the stores that could ever effect the load
// at %8 can be gotten by using the memory use associated with it,
// and walking from use to def until you hit the top of the function.

// Each def also has a list of users associated with it, so you can walk from
// both def to users, and users to defs.
// Note that we disambiguate MemoryUse's, but not the RHS of memorydefs.
// You can see this above at %8, which would otherwise be a MemoryUse(4)
// Being disambiguated means that for a given store, all the MemoryUses on its
// use lists are may-aliases of that store (but the MemoryDefs on its use list
// may not be)
//
// MemoryDefs are not disambiguated because it would require multiple reaching
// definitions, which would require multiple phis, and multiple memoryaccesses
// per instruction.

//===----------------------------------------------------------------------===//
#ifndef LLVM_TRANSFORMS_UTILS_MEMORYSSA_H
#define LLVM_TRANSFORMS_UTILS_MEMORYSSA_H
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/PHITransAddr.h"
#include "llvm/ADT/ilist_node.h"
#include "llvm/ADT/iterator.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/GraphTraits.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include <list>

namespace llvm {
	
void initializeMemorySSAPrinterPassPass(PassRegistry&);
void initializeMemorySSALazyPass(PassRegistry&);

class BasicBlock;
class DominatorTree;
class Function;
class MemoryAccess;
template <class T> class memoryaccess_def_iterator_base;
typedef memoryaccess_def_iterator_base<MemoryAccess> memoryaccess_def_iterator;
typedef memoryaccess_def_iterator_base<const MemoryAccess>
    const_memoryaccess_def_iterator;

// \brief The base for all memory accesses. All memory accesses in a
// block are linked together using an intrusive list.
class MemoryAccess : public ilist_node<MemoryAccess> {
public:
  enum AccessType { AccessUse, AccessDef, AccessPhi };

  // Methods for support type inquiry through isa, cast, and
  // dyn_cast
  static inline bool classof(const MemoryAccess *) { return true; }

  virtual ~MemoryAccess();
  BasicBlock *getBlock() const { return Block; }

  /// \brief Get the instruction that this MemoryAccess represents.
  /// This may be null in the case of phi nodes.
  virtual Instruction *getMemoryInst() const = 0;

  /// \brief Get the access that produces the memory state used by this access.
  virtual MemoryAccess *getDefiningAccess() const = 0;

  /// \brief Replace our defining access with a new one.
  ///
  /// This function updates use lists.
  virtual void setDefiningAccess(MemoryAccess *) = 0;

  virtual void print(raw_ostream &OS) const {};
  virtual void dump() const;

  typedef SmallPtrSet<MemoryAccess *, 8> UserListType;
  typedef UserListType::iterator iterator;
  typedef UserListType::const_iterator const_iterator;

  unsigned user_size() const { return Users.size(); }
  bool user_empty() const { return Users.empty(); }
  iterator user_begin() { return Users.begin(); }
  iterator user_end() { return Users.end(); }
  iterator_range<iterator> users() {
    return iterator_range<iterator>(user_begin(), user_end());
  }

  const_iterator user_begin() const { return Users.begin(); }
  const_iterator user_end() const { return Users.end(); }
  iterator_range<const_iterator> uses() const {
    return iterator_range<const_iterator>(user_begin(), user_end());
  }

  /// \brief This iterator walks over all of the defs in a given
  /// MemoryAccess. For MemoryPhi nodes, this walks arguments.  For
  /// MemoryUse/MemoryDef, this walks the defining access.
  memoryaccess_def_iterator defs_begin();
  const_memoryaccess_def_iterator defs_begin() const;
  memoryaccess_def_iterator defs_end();
  const_memoryaccess_def_iterator defs_end() const;

protected:
  friend class MemorySSA;
  friend class MemoryUse;
  friend class MemoryDef;
  friend class MemoryPhi;
  AccessType getAccessType() const { return AccessType; }

  /// \brief Set the instruction that this MemoryUse represents.
  virtual void setMemoryInst(Instruction *MI) = 0;

  /// \brief Add a use of this memory access to our list of uses.
  ///
  /// Note: We depend on being able to add the same use multiple times and not
  /// have it end up in our use list multiple times.
  void addUse(MemoryAccess *Use) { Users.insert(Use); }

  /// \brief Remove a use of this memory access from our list of uses.
  void removeUse(MemoryAccess *Use) { Users.erase(Use); }

  /// \brief Return true if \p Use is one of the uses of this memory access.
  bool hasUse(MemoryAccess *Use) { return Users.count(Use); }

  MemoryAccess(AccessType AT, BasicBlock *BB) : AccessType(AT), Block(BB) {}

  /// \brief Used internally to give IDs to MemoryAccesses for printing
  virtual unsigned int getID() const = 0;

private:
  MemoryAccess(const MemoryAccess &);
  void operator=(const MemoryAccess &);
  AccessType AccessType;
  BasicBlock *Block;
  UserListType Users;
};

template <>
struct ilist_traits<MemoryAccess> : public ilist_default_traits<MemoryAccess> {
  // See details of the instruction class for why this trick works
  MemoryAccess *createSentinel() const {
    return static_cast<MemoryAccess *>(&Sentinel);
  }

  static void destroySentinel(MemoryAccess *) {}

  MemoryAccess *provideInitialHead() const { return createSentinel(); }
  MemoryAccess *ensureHead(MemoryAccess *) const { return createSentinel(); }
  static void noteHead(MemoryAccess *, MemoryAccess *) {}

private:
  mutable ilist_half_node<MemoryAccess> Sentinel;
};

inline raw_ostream &operator<<(raw_ostream &OS, const MemoryAccess &MA) {
  MA.print(OS);
  return OS;
}

/// \brief Represents read-only accesses to memory
///
/// In particular, the set of Instructions that will be represented by
/// MemoryUse's is exactly the set of Instructions for which
/// AliasAnalysis::getModRefInfo returns "Ref".
class MemoryUse : public MemoryAccess {
public:
  MemoryUse(MemoryAccess *DMA, Instruction *MI, BasicBlock *BB)
      : MemoryUse(DMA, AccessUse, MI, BB) {}

  virtual MemoryAccess *getDefiningAccess() const final {
    return DefiningAccess;
  }

  virtual Instruction *getMemoryInst() const final { return MemoryInst; }

  static inline bool classof(const MemoryUse *) { return true; }
  static inline bool classof(const MemoryAccess *MA) {
    return MA->getAccessType() == AccessUse;
  }
  virtual void print(raw_ostream &OS) const;

protected:
  friend class MemorySSA;

  MemoryUse(MemoryAccess *DMA, enum AccessType AT, Instruction *MI,
            BasicBlock *BB)
      : MemoryAccess(AT, BB), DefiningAccess(nullptr), MemoryInst(MI) {
    setDefiningAccess(DMA);
  }
  virtual void setMemoryInst(Instruction *MI) final { MemoryInst = MI; }
  virtual void setDefiningAccess(MemoryAccess *DMA) final {
    if (DefiningAccess != DMA) {
      if (DefiningAccess)
        DefiningAccess->removeUse(this);
      if (DMA)
        DMA->addUse(this);
    }
    DefiningAccess = DMA;
  }
  virtual unsigned int getID() const {
    llvm_unreachable("MemoryUse's do not have ID's");
  }

private:
  MemoryAccess *DefiningAccess;
  Instruction *MemoryInst;
};

/// \brief Represents a read-write access to memory, whether it is a must-alias,
/// or a may-alias.
///
/// In particular, the set of Instructions that will be represented by
/// MemoryDef's is exactly the set of Instructions for which
/// AliasAnalysis::getModRefInfo returns "Mod" or "ModRef".
/// Note that, in order to provide def-def chains, all defs also have a use
/// associated with them.  This use points to the nearest reaching
/// MemoryDef/MemoryPhi.
class MemoryDef final : public MemoryUse {
public:
  MemoryDef(MemoryAccess *DMA, Instruction *MI, BasicBlock *BB, unsigned Ver)
      : MemoryUse(DMA, AccessDef, MI, BB), ID(Ver) {}

  static inline bool classof(const MemoryDef *) { return true; }
  static inline bool classof(const MemoryUse *MA) {
    return MA->getAccessType() == AccessDef;
  }

  static inline bool classof(const MemoryAccess *MA) {
    return MA->getAccessType() == AccessDef;
  }
  virtual void print(raw_ostream &OS) const;

protected:
  friend class MemorySSA;
  // For debugging only. This gets used to give memory accesses pretty numbers
  // when printing them out

  virtual unsigned int getID() const final { return ID; }

private:
  const unsigned int ID;
};

/// \brief Represents phi nodes for memory accesses.
///
/// These have the same semantic as regular phi nodes, with the exception that
/// only one phi will ever exist in a given basic block.
/// Guaranteeing one phi per block means guaranteeing there is only ever one
/// valid reaching MemoryDef/MemoryPHI along each path to the phi node.
/// This is ensured by not allowing disambiguation of the RHS of a MemoryDef or
/// a MemoryPhi's operands.
/// That is, given
/// if (a) {
///   store %a
///   store %b
/// }
/// it *must* be transformed into
/// if (a) {
///    1 = MemoryDef(liveOnEntry)
///    store %a
///    2 = MemoryDef(1)
///    store %b
/// }
/// and *not*
/// if (a) {
///    1 = MemoryDef(liveOnEntry)
///    store %a
///    2 = MemoryDef(liveOnEntry)
///    store %b
/// }
/// even if the two stores do not conflict.  Otherwise, both 1 and 2 reach the
/// end of the branch, and if there are not two phi nodes, one will be
/// disconnected completely from the SSA graph below that point.
/// Because MemoryUse's do not generate new definitions, they do not have this
/// issue.
class MemoryPhi final : public MemoryAccess {
public:
  MemoryPhi(BasicBlock *BB, unsigned int NP, unsigned int Ver)
      : MemoryAccess(AccessPhi, BB), ID(Ver), NumPreds(NP) {
    Operands.reserve(NumPreds);
  }

  virtual Instruction *getMemoryInst() const final {
    llvm_unreachable(
        "MemoryPhi's do not have a memory instruction associated with them");
  }

  virtual MemoryAccess *getDefiningAccess() const final {
    llvm_unreachable("MemoryPhi's do not have a single defining access");
  }

  /// \brief This is the number of actual predecessors this phi node has.
  unsigned int getNumPreds() const { return NumPreds; }

  /// \brief This is the number of incoming values currently in use
  ///
  /// During SSA construction, we differentiate between this and NumPreds to
  /// know when the PHI node is fully constructed.
  unsigned int getNumIncomingValues() const { return Operands.size(); }

  /// \brief Set the memory access of argument \p v of this phi node to be \p MA
  ///
  /// This function updates use lists.
  void setIncomingValue(unsigned int v, MemoryAccess *MA) {
    std::pair<BasicBlock *, MemoryAccess *> &Val = Operands[v];
    // We need to update use lists.  Because our uses are not to specific
    // operands, but instead to this MemoryAccess, and because a given memory
    // access may appear multiple times in the phi argument list, we need to be
    // careful not to remove the use of this phi, from MA, until we check to
    // make sure MA does not appear elsewhere in the phi argument list.
    if (Val.second != MA) {
      if (Val.second) {
        bool existsElsewhere = false;
        for (unsigned i = 0, e = Operands.size(); i != e; ++i) {
          if (i == v)
            continue;
          if (Operands[i].second == Val.second)
            existsElsewhere = true;
        }
        if (!existsElsewhere)
          Val.second->removeUse(this);
      }
      MA->addUse(this);
      Val.second = MA;
    }
  }

  MemoryAccess *getIncomingValue(unsigned int v) const {
    return Operands[v].second;
  }
  void setIncomingBlock(unsigned int v, BasicBlock *BB) {
    std::pair<BasicBlock *, MemoryAccess *> &Val = Operands[v];
    Val.first = BB;
  }
  BasicBlock *getIncomingBlock(unsigned int v) const {
    return Operands[v].first;
  }

  typedef SmallVector<std::pair<BasicBlock *, MemoryAccess *>, 8> OperandsType;
  typedef OperandsType::const_iterator const_op_iterator;
  inline const_op_iterator ops_begin() const { return Operands.begin(); }
  inline const_op_iterator ops_end() const { return Operands.end(); }
  inline iterator_range<const_op_iterator> operands() const {
    return iterator_range<const_op_iterator>(ops_begin(), ops_end());
  }

  static inline bool classof(const MemoryPhi *) { return true; }
  static inline bool classof(const MemoryAccess *MA) {
    return MA->getAccessType() == AccessPhi;
  }

  virtual void print(raw_ostream &OS) const;

protected:
  friend class MemorySSA;

  virtual void setDefiningAccess(MemoryAccess *) final {
    llvm_unreachable("MemoryPhi's do not have a single defining access");
  }
  virtual void setMemoryInst(Instruction *MI) final {}

  // MemorySSA currently cannot handle edge additions or deletions (but can
  // handle direct replacement).  This is protected to ensure people don't try.
  void addIncoming(MemoryAccess *MA, BasicBlock *BB) {
    Operands.push_back(std::make_pair(BB, MA));
    MA->addUse(this);
  }

  // For debugging only. This gets used to give memory accesses pretty numbers
  // when printing them out
  virtual unsigned int getID() const final { return ID; }

private:
  // For debugging only
  const unsigned ID;
  unsigned NumPreds;
  OperandsType Operands;
};

class MemorySSAWalker;

/// \brief Encapsulates MemorySSA, including all data associated with memory
/// accesses.
class MemorySSA {
public:
  MemorySSA(Function &);
  ~MemorySSA();

  /// \brief Build Memory SSA, and return the walker we used during building,
  /// for later reuse.  If MemorySSA is already built, just return the walker.
  MemorySSAWalker *buildMemorySSA(AliasAnalysis *, DominatorTree *);
  bool isFinishedBuilding() const { return builtAlready; }

  /// \brief Given a memory Mod/Ref'ing instruction, get the MemorySSA
  /// access associaed with it.  If passed a basic block gets the memory phi
  /// node that exists for that block, if there is one.
  MemoryAccess *getMemoryAccess(const Value *) const;
  void dump() const;
  void print(raw_ostream &) const;

  /// \brief Return true if \p MA represents the live on entry value
  ///
  /// Loads and stores from pointer arguments and other global values may be
  /// defined by memory operations that do not occur in the current function, so
  /// they may be live on entry to the function.  MemorySSA represents such
  /// memory state by the live on entry definition, which is guaranteed to
  /// occurr before any other memory access in the function.
  inline bool isLiveOnEntryDef(const MemoryAccess *MA) const {
    return MA == LiveOnEntryDef;
  }

  inline MemoryAccess *getLiveOnEntryDef() const {
    assert(LiveOnEntryDef && "Live on entry def not initialized yet");
    return LiveOnEntryDef;
  }

  typedef iplist<MemoryAccess> AccessListType;

  /// \brief Return the list of MemoryAccess's for a given basic block.
  ///
  /// This list is not modifiable by the user.
  const AccessListType *getBlockAccesses(const BasicBlock *BB) const {
    auto It = PerBlockAccesses.find(BB);
    if (It == PerBlockAccesses.end())
      return nullptr;
    return It->second.get();
  }

  /// \brief Remove a MemoryAccess from MemorySSA, including updating all
  /// definitions and uses.
  /// This should be called when a memory instruction that has a MemoryAccess
  /// associated with it is erased from the program.  For example, if a store or
  /// load is simply erased (not replaced), removeMemoryAccess should be called
  /// on the MemoryAccess for that store/load.
  void removeMemoryAccess(MemoryAccess *);

  /// \brief Replace one MemoryAccess with another, including updating all
  /// definitions and uses.
  /// This should be called when one memory instruction is being replaced with
  /// another.  For example, during GVN, a load may be replaced with another
  /// existing load. This function should be called to let MemorySSA know that
  /// this has happened
  void replaceMemoryAccess(MemoryAccess *Replacee, MemoryAccess *Replacer);

  enum InsertionPlace { Beginning, End };

  /// \brief Replace a MemoryAccess with a new access, created based on
  /// instruction \p Replacer - this does not perform generic SSA updates, so it
  /// only works if the new access dominates the old accesses uses.
  ///
  /// This API should be used if a new memory instruction has been added that is
  /// being used to replace an existing one.  For example, during store sinking,
  /// we may replace  a store sunk further down the CFG.  In that
  /// case, this function should be called with the MemoryAccess for the
  /// original store, and the new instruction replacing it.
  /// We may also merge two stores in two branches into a store after the
  /// branch.
  /// For example, we may have
  /// if (a) {
  ///   1 = MemoryDef(liveOnEntry)
  ///   store %a
  /// } else {
  ///   2 = MemoryDef(liveOnEntry)
  ///   store %a
  /// }
  /// 3 = MemoryPhi(1, 2)
  /// MemoryUse(3)
  /// load %a
  /// If the store is sunk below the branch, the correct update would be to call
  /// tihs function with the MemoryPhi and the new store, and removeAccess on
  /// the two old stores.
  /// This version places the access at either the end or the beginning of \p
  /// Replacer's block, depending on the value of \p Where.
  ///
  /// \returns the new access that was created.
  MemoryAccess *replaceMemoryAccessWithNewAccess(MemoryAccess *Replacee,
                                                 Instruction *Replacer,
                                                 enum InsertionPlace Where);
  /// \brief Replace a MemoryAccess with a new access, created based on
  /// instruction \p Replacer - this does not perform generic SSA updates, so it
  /// only works if the new access dominates the old accesses uses.
  ///
  /// This version places the access before the place that \p Where points to.
  MemoryAccess *
  replaceMemoryAccessWithNewAccess(MemoryAccess *Replacee,
                                   Instruction *Replacer,
                                   const AccessListType::iterator &Where);

  /// \brief Add a new MemoryUse for \p Use at the beginning or end of a block.
  ///
  /// This API is used to add MemoryUse's for new loads (or other memory Ref'ing
  /// instructions) to MemorySSA.  For example, if a load is hoisted and the old
  /// load eliminated, the proper update is to call addNewMemoryUse on the new
  /// load, and then replaceMemoryAccess with (old load, new load).
  MemoryAccess *addNewMemoryUse(Instruction *Use, enum InsertionPlace Where);

  /// \brief Given two memory accesses in the same basic block, determine
  /// whether MemoryAccess \p A dominates MemoryAccess \p B.
  bool locallyDominates(const MemoryAccess *A, const MemoryAccess *B) const;

protected:
  // Used by Memory SSA annotater, dumpers, and wrapper pass
  friend class MemorySSAAnnotatedWriter;
  friend class MemorySSAPrinterPass;
  void verifyDefUses(Function &F);
  void verifyDomination(Function &F);

private:
  void verifyUseInDefs(MemoryAccess *, MemoryAccess *);
  typedef DenseMap<const BasicBlock *, std::unique_ptr<AccessListType>>
      AccessMap;

  void
  determineInsertionPoint(const SmallPtrSetImpl<BasicBlock *> &DefiningBlocks);
  void computeDomLevels(DenseMap<DomTreeNode *, unsigned> &DomLevels);
  void markUnreachableAsLiveOnEntry(BasicBlock *BB);
  bool dominatesUse(const MemoryAccess *, const MemoryAccess *) const;
  void removeFromLookups(MemoryAccess *);
  MemoryAccess *createNewAccess(Instruction *, bool ignoreNonMemory = false);
  MemoryAccess *findDominatingDef(BasicBlock *, enum InsertionPlace);

  MemoryAccess *renameBlock(BasicBlock *, MemoryAccess *);
  void renamePass(DomTreeNode *, MemoryAccess *IncomingVal,
                  SmallPtrSet<BasicBlock *, 16> &Visited);
  std::unique_ptr<AccessListType> &getOrCreateAccessList(BasicBlock *);
  bool replaceAllOccurrences(MemoryPhi *, MemoryAccess *, MemoryAccess *);
  AliasAnalysis *AA;
  DominatorTree *DT;
  Function &F;

  // Memory SSA mappings
  DenseMap<const Value *, MemoryAccess *> InstructionToMemoryAccess;
  AccessMap PerBlockAccesses;
  MemoryAccess *LiveOnEntryDef;

  // Memory SSA building info
  unsigned int nextID;
  bool builtAlready;
  MemorySSAWalker *Walker;
};

// This pass does eager building and then printing of MemorySSA. It is used by
// the tests to be able to build, dump, and verify Memory SSA.

class MemorySSAPrinterPass : public FunctionPass {
public:
  MemorySSAPrinterPass();

  static char ID;
  bool doInitialization(Module &M) override;
  bool runOnFunction(Function &) override;
  void releaseMemory() override;
  void getAnalysisUsage(AnalysisUsage &AU) const override;
  void print(raw_ostream &OS, const Module *M) const override;
  static void registerOptions();
  MemorySSA &getMSSA() { return *MSSA; }

private:
  bool VerifyMemorySSA;

  MemorySSA *MSSA;
  MemorySSAWalker *Walker;
  Function *F;
};

class MemorySSALazy : public FunctionPass {
public:
  MemorySSALazy();

  static char ID;
  bool runOnFunction(Function &) override;
  void releaseMemory() override;
  MemorySSA &getMSSA() { return *MSSA; }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesAll();
  }

private:
  MemorySSA *MSSA;
};

/// \brief This is the generic walker interface for walkers of MemorySSA.
/// Walkers are used to be able to further disambiguate the def-use chains
/// MemorySSA gives you, or otherwise produce better info than MemorySSA gives
/// you.
/// In particular, while the def-use chains provide basic information, and are
/// guaranteed to give, for example, the nearest may-aliasing MemoryDef for a
/// MemoryUse as AliasAnalysis considers it, a user mant want better or other
/// information. In particular, they may want to use SCEV info to further
/// disambiguate memory accesses, or they may want the nearest dominating
/// may-aliasing MemoryDef for a call or a store.  This API enables a
/// standardized interface to getting and using that info.

class MemorySSAWalker {
public:
  MemorySSAWalker(MemorySSA *);
  virtual ~MemorySSAWalker() {}

  typedef SmallVector<MemoryAccess *, 8> MemoryAccessSet;
  /// \brief Given a memory Mod/Ref/ModRef'ing instruction, calling this
  /// will give you the nearest dominating MemoryAccess that Mod's the location
  /// the instruction accesses (by skipping any def which AA can prove does not
  /// alias the location(s) accessed by the instruction given).
  ///
  /// Note that this will return a single access, and it must dominate the
  /// Instruction, so if an operand of a MemoryPhi node Mod's the instruction,
  /// this will return the MemoryPhi, not the operand.  This means that
  /// given:
  /// if (a) {
  ///   1 = MemoryDef(liveOnEntry)
  ///   store %a
  /// } else {
  ///   2 = MemoryDef(liveOnEntry)
  ///    store %b
  /// }
  /// 3 = MemoryPhi(2, 1)
  /// MemoryUse(3)
  /// load %a
  ///
  /// calling this API on load(%a) will return the MemoryPhi, not the MemoryDef
  /// in the if (a) branch.
  virtual MemoryAccess *getClobberingMemoryAccess(const Instruction *) = 0;

  /// \brief Given a potentially clobbering memory access and a new location,
  /// calling this will give you the nearest dominating clobbering MemoryAccess
  /// (by skipping non-aliasing def links).
  ///
  /// This version of the function is mainly used to disambiguate phi translated
  /// pointers, where the value of a pointer may have changed from the initial
  /// memory access.  Note that this expects to be handed either a memory use,
  /// or an already potentially clobbering access.  Unlike the above API, if
  /// given a MemoryDef that clobbers the pointer as the starting access, it
  /// will return that MemoryDef, whereas the above would return the clobber
  /// starting from the use side of  the memory def.
  virtual MemoryAccess *getClobberingMemoryAccess(MemoryAccess *,
                                                  MemoryLocation &) = 0;

  /// \brief Given a memory access, invalidate anything this walker knows about
  /// that access.
  /// This API is used by walkers that store information to perform basic cache
  /// invalidation.  This will be called by MemorySSA at appropriate times for
  /// the walker it uses or returns through getWalker.
  virtual void invalidateInfo(MemoryAccess *){};

protected:
  MemorySSA *MSSA;
};

/// \brief A MemorySSAWalker that does no alias queries, or anything else. It
/// simply returns the links as they were constructed by the builder.
class DoNothingMemorySSAWalker final : public MemorySSAWalker {
public:
  MemoryAccess *getClobberingMemoryAccess(const Instruction *) override;
  MemoryAccess *getClobberingMemoryAccess(MemoryAccess *,
                                          MemoryLocation &) override;
};
typedef std::pair<MemoryAccess *, MemoryLocation> MemoryAccessPair;
typedef std::pair<const MemoryAccess *, MemoryLocation> ConstMemoryAccessPair;

/// \brief A MemorySSAWalker that does AA walks and caching of lookups to
/// disambiguate accesses.
class CachingMemorySSAWalker final : public MemorySSAWalker {
public:
  CachingMemorySSAWalker(MemorySSA *, AliasAnalysis *, DominatorTree *);
  virtual ~CachingMemorySSAWalker();
  MemoryAccess *getClobberingMemoryAccess(const Instruction *) override;
  MemoryAccess *getClobberingMemoryAccess(MemoryAccess *,
                                          MemoryLocation &) override;
  void invalidateInfo(MemoryAccess *) override;

protected:
  struct UpwardsMemoryQuery;
  MemoryAccess *doCacheLookup(const MemoryAccess *, const UpwardsMemoryQuery &,
                              const MemoryLocation &);

  void doCacheInsert(const MemoryAccess *, MemoryAccess *,
                     const UpwardsMemoryQuery &, const MemoryLocation &);

  void doCacheRemove(const MemoryAccess *, const UpwardsMemoryQuery &,
                     const MemoryLocation &);

private:
  MemoryAccessPair UpwardsDFSWalk(MemoryAccess *, const MemoryLocation &,
                                  UpwardsMemoryQuery &, bool);

  MemoryAccess *getClobberingMemoryAccess(MemoryAccess *,
                                          struct UpwardsMemoryQuery &);
  bool instructionClobbersQuery(const MemoryDef *, struct UpwardsMemoryQuery &,
                                const MemoryLocation &Loc) const;
  SmallDenseMap<ConstMemoryAccessPair, MemoryAccess *>
      CachedUpwardsClobberingAccess;
  DenseMap<const MemoryAccess *, MemoryAccess *> CachedUpwardsClobberingCall;
  AliasAnalysis *AA;
  DominatorTree *DT;
};

/// \brief Iterator base class used to implement const and non-const iterators
/// over the defining accesses of a MemoryAccess.
template <class T>
class memoryaccess_def_iterator_base
    : public iterator_facade_base<memoryaccess_def_iterator_base<T>,
                                  std::forward_iterator_tag, T, ptrdiff_t, T *,
                                  T *> {
  typedef typename memoryaccess_def_iterator_base::iterator_facade_base BaseT;

public:
  memoryaccess_def_iterator_base(T *Start) : Access(Start), ArgNo(0) {}
  memoryaccess_def_iterator_base() : Access(nullptr), ArgNo(0) {}
  bool operator==(const memoryaccess_def_iterator_base &Other) const {
    if (Access == nullptr)
      return Other.Access == nullptr;
    return Access == Other.Access && ArgNo == Other.ArgNo;
  }

  // This is a bit ugly, but for MemoryPHI's, unlike PHINodes, you can't get the
  // block from the operand in constant time (In a PHINode, the uselist has
  // both, so it's just subtraction).  We provide it as part of the
  // iterator to avoid callers having to linear walk to get the block.
  // If the operation becomes constant time on MemoryPHI's, this bit of
  // abstraction breaking should be removed.
  BasicBlock *getPhiArgBlock() const {
    MemoryPhi *MP = dyn_cast<MemoryPhi>(Access);
    assert(MP && "Tried to get phi arg block when not iterating over a PHI");
    return MP->getIncomingBlock(ArgNo);
  }
  typename BaseT::iterator::pointer operator*() const {
    assert(Access && "Tried to access past the end of our iterator");
    // Go to the first argument for phis, and the defining access for everything
    // else.
    if (MemoryPhi *MP = dyn_cast<MemoryPhi>(Access))
      return MP->getIncomingValue(ArgNo);
    return Access->getDefiningAccess();
  }
  using BaseT::operator++;
  memoryaccess_def_iterator &operator++() {
    assert(Access && "Hit end of iterator");
    if (MemoryPhi *MP = dyn_cast<MemoryPhi>(Access)) {
      if (++ArgNo >= MP->getNumIncomingValues()) {
        ArgNo = 0;
        Access = nullptr;
      }
    } else {
      Access = nullptr;
    }
    return *this;
  }

private:
  T *Access;
  unsigned ArgNo;
};

inline memoryaccess_def_iterator MemoryAccess::defs_begin() {
  return memoryaccess_def_iterator(this);
}
inline const_memoryaccess_def_iterator MemoryAccess::defs_begin() const {
  return const_memoryaccess_def_iterator(this);
}

inline memoryaccess_def_iterator MemoryAccess::defs_end() {
  return memoryaccess_def_iterator();
}

inline const_memoryaccess_def_iterator MemoryAccess::defs_end() const {
  return const_memoryaccess_def_iterator();
}

/// \brief GraphTraits for a MemoryAccess, which walks defs in the normal case,
/// and uses in the inverse case.
template <> struct GraphTraits<MemoryAccess *> {
  typedef MemoryAccess NodeType;
  typedef memoryaccess_def_iterator ChildIteratorType;

  static NodeType *getEntryNode(NodeType *N) { return N; }
  static inline ChildIteratorType child_begin(NodeType *N) {
    return N->defs_begin();
  }
  static inline ChildIteratorType child_end(NodeType *N) {
    return N->defs_end();
  }
};

template <> struct GraphTraits<Inverse<MemoryAccess *>> {
  typedef MemoryAccess NodeType;
  typedef MemoryAccess::iterator ChildIteratorType;

  static NodeType *getEntryNode(NodeType *N) { return N; }
  static inline ChildIteratorType child_begin(NodeType *N) {
    return N->user_begin();
  }
  static inline ChildIteratorType child_end(NodeType *N) {
    return N->user_end();
  }
};

/// \brief Provide an iterator that walks defs, giving both the memory access,
/// and the current pointer location, updating the pointer location as it
/// changes due to phi node translation.
///
/// This iterator, while somewhat specialized, is what most clients actually
/// want when walking upwards through MemorySSA def chains.  It takes a pair of
/// <MemoryAccess,MemoryLocation>, and walks defs, properly translating the
/// memory location through phi nodes for the user.
class upward_defs_iterator
    : public iterator_facade_base<upward_defs_iterator,
                                  std::forward_iterator_tag,
                                  const MemoryAccessPair> {
  typedef typename upward_defs_iterator::iterator_facade_base BaseT;

public:
  upward_defs_iterator(const MemoryAccessPair &Info)
      : DefIterator(Info.first), Location(Info.second),
        OriginalAccess(Info.first) {
    CurrentPair.first = nullptr;

    if (Info.first)
      WalkingPhi = isa<MemoryPhi>(Info.first);
    fillInCurrentPair();
  }
  upward_defs_iterator() : DefIterator(), Location(), OriginalAccess() {
    CurrentPair.first = nullptr;
  }
  bool operator==(const upward_defs_iterator &Other) const {
    return DefIterator == Other.DefIterator;
  }

  typename BaseT::iterator::reference operator*() const {
    assert(DefIterator != OriginalAccess->defs_end() &&
           "Tried to access past the end of our iterator");
    return CurrentPair;
  }
  using BaseT::operator++;

  upward_defs_iterator &operator++() {
    assert(DefIterator != OriginalAccess->defs_end() &&
           "Tried to access past the end of the iterator");
    ++DefIterator;
    if (DefIterator != OriginalAccess->defs_end())
      fillInCurrentPair();
    return *this;
  }

  BasicBlock *getPhiArgBlock() const { return DefIterator.getPhiArgBlock(); }

private:
  void fillInCurrentPair() {
    CurrentPair.first = *DefIterator;
    if (WalkingPhi && Location.Ptr) {
      PHITransAddr Translator(
          const_cast<Value *>(Location.Ptr),
          OriginalAccess->getBlock()->getModule()->getDataLayout(), nullptr);
      if (!Translator.PHITranslateValue(OriginalAccess->getBlock(),
                                        DefIterator.getPhiArgBlock(), nullptr,
                                        false))
        if (Translator.getAddr() != Location.Ptr) {
          CurrentPair.second = Location.getWithNewPtr(Translator.getAddr());
          return;
        }
    }
    CurrentPair.second = Location;
  }

  MemoryAccessPair CurrentPair;
  memoryaccess_def_iterator DefIterator;
  MemoryLocation Location;
  bool WalkingPhi;
  MemoryAccess *OriginalAccess;
};

inline upward_defs_iterator upward_defs_begin(const MemoryAccessPair &Pair) {
  return upward_defs_iterator(Pair);
}
inline upward_defs_iterator upward_defs_end() { return upward_defs_iterator(); }
}

#endif
