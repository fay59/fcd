//
// pass_typerec.cpp
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

#include "metadata.h"
#include "passes.h"
#include "pointer_discovery.h"

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include <unordered_set>
#include <vector>

using namespace std;
using namespace llvm;

namespace
{
	class CompoundTypeState;
	
	struct CompoundTypeField
	{
		enum Type
		{
			Load,
			Store,
			Call,
		};
		
		Type type;
		NOT_NULL(CompoundTypeState) parent;
		NOT_NULL(ObjectAddress) accessAddress;
		
		union
		{
			Instruction* load;
			Instruction* store;
			struct
			{
				Use* callParameter;
				CompoundTypeState* passedAs;
			};
			// implementation detail
			struct
			{
				void* p0_;
				void* p1_;
			};
		};
		
		CompoundTypeField(CompoundTypeState& parent, LoadInst& load, ObjectAddress& access)
		: type(Load), parent(&parent), accessAddress(&access), load(&load)
		{
		}
		
		CompoundTypeField(CompoundTypeState& parent, StoreInst& store, ObjectAddress& access)
		: type(Store), parent(&parent), accessAddress(&access), store(&store)
		{
		}
		
		CompoundTypeField(CompoundTypeState& parent, Use& callParameter, CompoundTypeState& parameterType, ObjectAddress& access)
		: type(Call), parent(&parent), accessAddress(&access), callParameter(&callParameter), passedAs(&parameterType)
		{
		}
		
		CompoundTypeField& operator=(const CompoundTypeField& that)
		{
			type = that.type;
			parent = that.parent;
			accessAddress = that.accessAddress;
			p0_ = that.p0_;
			p1_ = that.p1_;
			return *this;
		}
	};
	
	struct CompoundTypeFieldOffsetComparator
	{
		bool operator()(const CompoundTypeField& a, const CompoundTypeField& b) const
		{
			return a.accessAddress->getOrderingKey().second < b.accessAddress->getOrderingKey().second;
		}
	};
	
	class CompoundTypeState
	{
		RootObjectAddress& definingObjectAddress;
		
		// A supertype represents a common sequence of fields that this type includes. For instance, a sequence
		// { float, int* } could be a supertype of { float, int*, double } (starting at offset 0) as well as a supertype
		// of { double, float, int* } (starting at offset 8).
		unordered_set<CompoundTypeState*> supertypes;
		
		// A subtype represents a type that extends this sequence of fields, with "sub" used in its usual OO meaning:
		// the instances of that type are a subset of all the instances of the supertype.
		unordered_set<CompoundTypeState*> subtypes;
		
		// Fields are added when subtypes are unified and when a memory access is discovered in a location that post-
		// dominates this use.
		vector<CompoundTypeField> fields;
		
		template<typename... Args>
		void insertField(Args&&... args)
		{
			CompoundTypeField newField(*this, forward<Args>(args)...);
			auto insertLocation = upper_bound(fields.begin(), fields.end(), newField, CompoundTypeFieldOffsetComparator());
			fields.insert(insertLocation, newField);
		}
		
	public:
		CompoundTypeState(RootObjectAddress& definingObjectAddress)
		: definingObjectAddress(definingObjectAddress)
		{
		}
		
		CompoundTypeState(CompoundTypeState& that)
		: definingObjectAddress(that.definingObjectAddress), supertypes(that.supertypes), subtypes(that.subtypes)
		{
			// This constructor should never be used to build an object on the stack.
			assert(this < __builtin_frame_address(2) || this > __builtin_frame_address(1));
			
			for (auto field : that.fields)
			{
				field.parent = this;
				fields.push_back(field);
			}
			
			supertypes.insert(&that);
			for (const auto& supertype : supertypes)
			{
				supertype->subtypes.insert(this);
			}
		}
		
		void apply(ObjectAddress& location, LoadInst& load)
		{
			assert(&location.getRoot() == &definingObjectAddress);
			insertField(load, location);
		}
		
		void apply(ObjectAddress& location, StoreInst& store)
		{
			assert(&location.getRoot() == &definingObjectAddress);
			insertField(store, location);
		}
		
		void apply(ObjectAddress& location, Use& callUse, CompoundTypeState& type)
		{
			assert(&location.getRoot() == &definingObjectAddress);
			insertField(callUse, type, location);
			subtypes.insert(&type);
			type.supertypes.insert(this);
		}
	};
	
	struct TypeRegistry
	{
		deque<CompoundTypeState> types;
		unordered_map<RootObjectAddress*, unordered_map<DomTreeNode*, CompoundTypeState*>> typeForAddress;
		
		// This assumes that basic blocks are visited in reverse post-order, such that a parent is certain to have been
		// visited at the point that a child is.
		// Note that domNode may be null (indicating that address.value is an Argument).
		CompoundTypeState& getForAddress(ObjectAddress& address, DomTreeNode* domNode)
		{
			RootObjectAddress& root = address.getRoot();
			auto& typeForTreeNode = typeForAddress[&root];
			
			DomTreeNode* domTreeIter = domNode;
			while (domTreeIter != nullptr)
			{
				if (typeForTreeNode.count(domTreeIter) != 0)
				{
					break;
				}
				domTreeIter = domTreeIter->getIDom();
			}
			
			auto iter = typeForTreeNode.find(domTreeIter);
			if (iter == typeForTreeNode.end())
			{
				assert(&root == &address);
				types.emplace_back(root);
				typeForTreeNode[domNode] = &types.back();
				return types.back();
			}
			else
			{
				CompoundTypeState* type;
				if (domTreeIter == domNode)
				{
					type = iter->second;
				}
				else
				{
					types.emplace_back(*iter->second);
					type = &types.back();
					typeForTreeNode[domNode] = type;
				}
				return *type;
			}
		}
	};
	
	unsigned getDominatorTreeRowIndex(DominatorTree& domTree, Instruction& value)
	{
		unsigned count = 0;
		for (DomTreeNode* domNode = domTree.getNode(value.getParent()); domNode != nullptr; domNode = domNode->getIDom())
		{
			++count;
		}
		return count;
	}
}

char TypeRecovery::ID = 0;

TypeRecovery::TypeRecovery()
: ModulePass(ID)
{
}

TypeRecovery::~TypeRecovery()
{
}

void TypeRecovery::getAnalysisUsage(AnalysisUsage& au) const
{
	au.addRequired<ExecutableWrapper>();
	au.addPreserved<ExecutableWrapper>();
	au.addRequired<DominatorTreeWrapperPass>();
	au.addPreserved<DominatorTreeWrapperPass>();
}

bool TypeRecovery::doInitialization(Module& module)
{
	auto i8T = Type::getInt8Ty(module.getContext());
	auto sizeT = Type::getIntNTy(module.getContext(), module.getDataLayout().getPointerSizeInBits());
	FunctionType* adjustPointerType = FunctionType::get(i8T, { i8T, sizeT }, false);
	adjustPointer = module.getOrInsertFunction("fcd.adjust.ptr", adjustPointerType);
	return true;
}

bool TypeRecovery::runOnModule(Module& module)
{
	bool changed = false;
	
	pointers.reset(new PointerDiscovery);
	pointers->analyzeModule(*getAnalysis<ExecutableWrapper>().getExecutable(), module);
	
	deque<ObjectAddress*> addresses;
	for (Function& fn : module)
	{
		if (auto addressesInFunction = pointers->getAddressesInFunction(fn))
		{
			addresses.insert(addresses.end(), addressesInFunction->begin(), addressesInFunction->end());
		}
	}
	
	unordered_map<Instruction*, unsigned> instructionIndices;
	TypeRegistry registry;
	// Process roots.
	// (Opportunistically store instruction's position inside parent basic block for sorting purposes.)
	for (ObjectAddress* address : addresses)
	{
		if (auto root = dyn_cast<RootObjectAddress>(address))
		{
			DomTreeNode* treeNode;
			if (isa<Argument>(root->value))
			{
				treeNode = nullptr;
			}
			else
			{
				auto inst = cast<Instruction>(root->value);
				DominatorTree& domTree = getAnalysis<DominatorTreeWrapperPass>(*inst->getParent()->getParent()).getDomTree();
				treeNode = domTree.getNode(inst->getParent());
			}
			(void) registry.getForAddress(*root, treeNode);
		}
		
		if (auto inst = dyn_cast<Instruction>(address->value))
		{
			auto insertResult = instructionIndices.insert({inst, 0});
			if (insertResult.second)
			{
				unsigned& count = insertResult.first->second;
				for (auto iter = inst->getParent()->begin(); &*iter != inst; ++iter)
				{
					++count;
				}
			}
		}
	}
	
	// Sort object addresses by dominator tree row index and then by instruction index. This ensures that we always
	// process parent addresses first.
	sort(addresses.begin(), addresses.end(), [this, &instructionIndices] (ObjectAddress* a, ObjectAddress* b)
	{
		pair<unsigned, unsigned> aKey = {};
		pair<unsigned, unsigned> bKey = {};
		if (auto inst = dyn_cast<Instruction>(a->value))
		{
			DominatorTree& domTree = getAnalysis<DominatorTreeWrapperPass>(*inst->getParent()->getParent()).getDomTree();
			aKey.first = getDominatorTreeRowIndex(domTree, *inst);
			aKey.second = instructionIndices.at(inst);
		}
		if (auto inst = dyn_cast<Instruction>(b->value))
		{
			DominatorTree& domTree = getAnalysis<DominatorTreeWrapperPass>(*inst->getParent()->getParent()).getDomTree();
			bKey.first = getDominatorTreeRowIndex(domTree, *inst);
			bKey.second = instructionIndices.at(inst);
		}
		return aKey < bKey;
	});
	
	// Build up structures. Beyond that point, we don't have to care too much about object addresses except for arrays.
	for (ObjectAddress* address : addresses)
	{
		for (Use& use : address->value->uses())
		{
			if (auto inst = dyn_cast<Instruction>(use.get()))
			{
				DominatorTree& domTree = getAnalysis<DominatorTreeWrapperPass>(*inst->getParent()->getParent()).getDomTree();
				DomTreeNode* treeNode = domTree.getNode(inst->getParent());
				
				if (auto load = dyn_cast<LoadInst>(inst))
				{
					registry.getForAddress(*address, treeNode).apply(*address, *load);
				}
				else if (auto store = dyn_cast<StoreInst>(inst))
				{
					registry.getForAddress(*address, treeNode).apply(*address, *store);
				}
				else if (auto call = dyn_cast<CallInst>(inst))
				{
					if (auto func = call->getCalledFunction())
					{
						unsigned argNumber = use.getOperandNo() - call->getArgOperandUse(0).getOperandNo();
						auto argIter = func->arg_begin();
						advance(argIter, argNumber);
						if (auto callRoot = dyn_cast_or_null<RootObjectAddress>(pointers->getAddressOfArgument(*argIter)))
						{
							CompoundTypeState& thisObject = registry.getForAddress(*address, treeNode);
							CompoundTypeState& callParameterType = registry.getForAddress(*callRoot, nullptr);
							thisObject.apply(*address, use, callParameterType);
						}
					}
				}
			}
		}
	}
	
	return changed;
}

RegisterPass<TypeRecovery> typeRecovery("typerecovery", "Recover structure behind pointers");

ModulePass* createTypeRecoveryPass()
{
	return new TypeRecovery;
}
