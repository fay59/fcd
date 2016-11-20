//
// pre_ast_cfg_traits.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is part of fcd.
// 
// fcd is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// fcd is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with fcd.  If not, see <http://www.gnu.org/licenses/>.
//

#ifndef pre_ast_cfg_traits_h
#define pre_ast_cfg_traits_h

#include "pre_ast_cfg.h"

#include <iterator>

// I know that this is nasty and violates ODR, but I don't know what else to do. RegionInfoBase has a private
// constructor and destructor, which makes it impossible to create a subclass that is not friended in.
// This macro is ugly enough that we will most likely know right away if it expands in unexpected locations.
class PreAstRegionInfo;
#define MachineRegionInfo MachineRegionInfo; friend class ::PreAstRegionInfo
#include <llvm/Analysis/RegionInfo.h>
#undef MachineRegionInfo

#include <llvm/Analysis/DominanceFrontier.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/RegionIterator.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Dominators.h>
#include <llvm/Support/GenericDomTree.h>
#include <llvm/Support/GenericDomTreeConstruction.h>

class PreAstLoop;

struct PreAstBasicBlockRegionTraits
{
	typedef PreAstContext FuncT;
	typedef PreAstBasicBlock BlockT;
	typedef llvm::RegionBase<PreAstBasicBlockRegionTraits> RegionT;
	typedef llvm::RegionNodeBase<PreAstBasicBlockRegionTraits> RegionNodeT;
	typedef PreAstRegionInfo RegionInfoT;
	typedef llvm::DominatorTreeBase<PreAstBasicBlock> DomTreeT;
	typedef llvm::DomTreeNodeBase<PreAstBasicBlock> DomTreeNodeT;
	typedef llvm::ForwardDominanceFrontierBase<PreAstBasicBlock> DomFrontierT;
	typedef llvm::DominatorTreeBase<PreAstBasicBlock> PostDomTreeT;
	typedef llvm::Instruction InstT;
	typedef PreAstLoop LoopT;
	typedef llvm::LoopInfoBase<PreAstBasicBlock, LoopT> LoopInfoT;
};

template<typename Collection, NOT_NULL(PreAstBasicBlock) PreAstBasicBlockEdge::*EndSelector>
struct PreAstBasicBlockIterator : public std::iterator<std::input_iterator_tag, NOT_NULL(PreAstBasicBlock)>
{
	typename Collection::iterator base;
	
	PreAstBasicBlockIterator(typename Collection::iterator base)
	: base(base)
	{
	}
	
	PreAstBasicBlock* operator*() const
	{
		return (*base)->*EndSelector;
	}
	
	PreAstBasicBlockIterator& operator++()
	{
		++base;
		return *this;
	}
	
	PreAstBasicBlockIterator operator++(int)
	{
		auto copy = *this;
		++*this;
		return copy;
	}
	
	difference_type operator-(const PreAstBasicBlockIterator& that) const
	{
		return base - that.base;
	}
	
	bool operator==(const PreAstBasicBlockIterator& that) const
	{
		return base == that.base;
	}
	
	bool operator!=(const PreAstBasicBlockIterator& that) const
	{
		return !(base == that.base);
	}
};

template<>
struct llvm::GraphTraits<PreAstBasicBlock*>
{
	typedef PreAstBasicBlock NodeType;
	typedef NodeType* NodeRef;
	typedef PreAstBasicBlockIterator<decltype(PreAstBasicBlock().successors), &PreAstBasicBlockEdge::to> ChildIteratorType;
	
	static NodeType* getEntryNode(PreAstBasicBlock* block)
	{
		return block;
	}
	
	static ChildIteratorType child_begin(NodeType* node)
	{
		return ChildIteratorType(node->successors.begin());
	}
	
	static ChildIteratorType child_end(NodeType* node)
	{
		return ChildIteratorType(node->successors.end());
	}
};

template<>
struct llvm::GraphTraits<llvm::Inverse<PreAstBasicBlock*>>
{
	typedef PreAstBasicBlock NodeType;
	typedef NodeType* NodeRef;
	typedef PreAstBasicBlockIterator<decltype(PreAstBasicBlock().predecessors), &PreAstBasicBlockEdge::from> ChildIteratorType;
	
	static NodeType* getEntryNode(PreAstContext* context)
	{
		return context->getEntryBlock();
	}
	
	static ChildIteratorType child_begin(NodeType* node)
	{
		return ChildIteratorType(node->predecessors.begin());
	}
	
	static ChildIteratorType child_end(NodeType* node)
	{
		return ChildIteratorType(node->predecessors.end());
	}
};

struct PreAstContextGraphTraits
{
	typedef PreAstContext::node_iterator nodes_iterator;
	
	static nodes_iterator nodes_begin(PreAstContext* f)
	{
		return f->begin();
	}
	
	static nodes_iterator nodes_end(PreAstContext* f)
	{
		return f->end();
	}
	
	static size_t size(PreAstContext* f)
	{
		return f->size();
	}
	
	static PreAstBasicBlock* getEntryNode(PreAstContext* context)
	{
		return context->getEntryBlock();
	}
};

template<>
struct llvm::GraphTraits<PreAstContext*>
	: public llvm::GraphTraits<PreAstBasicBlock*>, public PreAstContextGraphTraits
{
	using llvm::GraphTraits<PreAstBasicBlock*>::getEntryNode;
	using PreAstContextGraphTraits::getEntryNode;
};

template<>
struct llvm::GraphTraits<llvm::Inverse<PreAstContext*>>
	: public llvm::GraphTraits<Inverse<PreAstBasicBlock*>>, public PreAstContextGraphTraits
{
	using llvm::GraphTraits<Inverse<PreAstBasicBlock*>>::getEntryNode;
	using PreAstContextGraphTraits::getEntryNode;
};

template<>
struct llvm::GraphTraits<PreAstBasicBlockRegionTraits::DomTreeNodeT*>
	: public llvm::DomTreeGraphTraitsBase<PreAstBasicBlockRegionTraits::DomTreeNodeT, PreAstBasicBlockRegionTraits::DomTreeNodeT::iterator>
{
};

template<>
struct llvm::GraphTraits<const PreAstBasicBlockRegionTraits::DomTreeNodeT*>
	: public llvm::DomTreeGraphTraitsBase<const PreAstBasicBlockRegionTraits::DomTreeNodeT, PreAstBasicBlockRegionTraits::DomTreeNodeT::const_iterator>
{
};

class PreAstLoop
	: public llvm::LoopBase<PreAstBasicBlock, PreAstLoop>
{
public:
	PreAstLoop(PreAstBasicBlock* bb)
	: llvm::LoopBase<PreAstBasicBlock, PreAstLoop>(bb)
	{
	}
};

class PreAstRegionInfo : public llvm::RegionInfoBase<PreAstBasicBlockRegionTraits>
{
public:
	PreAstRegionInfo();
	virtual ~PreAstRegionInfo() override = default;
	
	void recalculate(FuncT& function, DomTreeT* domTree, PostDomTreeT* postDomTree, DomFrontierT* dominanceFrontier);
	virtual void updateStatistics(PreAstBasicBlockRegionTraits::RegionT *R) override;
};

template<>
template<>
inline PreAstBasicBlockRegionTraits::BlockT* llvm::RegionNodeBase<PreAstBasicBlockRegionTraits>::getNodeAs<PreAstBasicBlockRegionTraits::BlockT>() const
{
	assert(!isSubRegion() && "This is not a block RegionNode!");
	return getEntry();
}

template<>
template<>
inline PreAstBasicBlockRegionTraits::RegionT* llvm::RegionNodeBase<PreAstBasicBlockRegionTraits>::getNodeAs<PreAstBasicBlockRegionTraits::RegionT>() const
{
	assert(!isSubRegion() && "This is not a block RegionNode!");
	auto unconst = const_cast<RegionNodeBase<PreAstBasicBlockRegionTraits>*>(this);
	return reinterpret_cast<RegionT*>(unconst);
}

namespace llvm
{
	RegionNodeGraphTraits(PreAstBasicBlockRegionTraits::RegionNodeT, PreAstBasicBlockRegionTraits::BlockT, PreAstBasicBlockRegionTraits::RegionT);
	RegionNodeGraphTraits(const PreAstBasicBlockRegionTraits::RegionNodeT, PreAstBasicBlockRegionTraits::BlockT, PreAstBasicBlockRegionTraits::RegionT);
	
	RegionGraphTraits(PreAstBasicBlockRegionTraits::RegionT, PreAstBasicBlockRegionTraits::RegionNodeT);
	RegionGraphTraits(const PreAstBasicBlockRegionTraits::RegionT, const PreAstBasicBlockRegionTraits::RegionNodeT);
}

#endif /* pre_ast_cfg_traits_h */
