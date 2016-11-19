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

#include <llvm/Analysis/DominanceFrontier.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/RegionInfo.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Dominators.h>
#include <llvm/Support/GenericDomTree.h>
#include <llvm/Support/GenericDomTreeConstruction.h>

template<typename Collection, NOT_NULL(PreAstBasicBlock) PreAstBasicBlockEdge::*EndSelector>
struct PreAstBasicBlockIterator : public std::iterator<std::input_iterator_tag, NOT_NULL(PreAstBasicBlock)>
{
	typename Collection::iterator base;
	
	PreAstBasicBlockIterator(typename Collection::iterator base)
	: base(base)
	{
	}
	
	reference operator*()
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
	
	bool operator==(const PreAstBasicBlockIterator& that) const
	{
		return base == that.base;
	}
	
	bool operator!=(const PreAstBasicBlockIterator& that) const
	{
		return !(base == that.base);
	}
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

struct PreAstBasicBlockRegionTraits
{
	typedef PreAstContext FuncT;
	typedef PreAstBasicBlock BlockT;
	typedef llvm::RegionBase<PreAstBasicBlockRegionTraits> RegionT;
	typedef llvm::RegionNodeBase<PreAstBasicBlockRegionTraits> RegionNodeT;
	typedef llvm::RegionInfoBase<PreAstBasicBlockRegionTraits> RegionInfoT;
	typedef llvm::DominatorTreeBase<PreAstBasicBlock> DomTreeT;
	typedef llvm::DomTreeNodeBase<PreAstBasicBlock> DomTreeNodeT;
	typedef llvm::DominanceFrontierBase<PreAstBasicBlock> DomFrontierT;
	typedef llvm::DominatorTreeBase<PreAstBasicBlock> PostDomTreeT;
	typedef llvm::Instruction InstT;
	typedef PreAstLoop LoopT;
	typedef llvm::LoopInfoBase<PreAstBasicBlock, LoopT> LoopInfoT;
};

template<>
struct llvm::GraphTraits<PreAstBasicBlock*>
{
	typedef PreAstBasicBlock NodeType;
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
struct llvm::GraphTraits<const PreAstBasicBlockRegionTraits::DomTreeNodeT*>
	: public llvm::DomTreeGraphTraitsBase<const PreAstBasicBlockRegionTraits::DomTreeNodeT, PreAstBasicBlockRegionTraits::DomTreeNodeT::const_iterator>
{
};

#endif /* pre_ast_cfg_traits_h */
