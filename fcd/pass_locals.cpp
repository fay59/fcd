//
// pass_locals.cpp
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

#include "dumb_allocator.h"
#include "metadata.h"
#include "passes.h"

#include <llvm/IR/PatternMatch.h>

#include <deque>
#include <map>
#include <unordered_map>
#include <vector>

using namespace llvm;
using namespace llvm::PatternMatch;
using namespace std;

namespace
{
	template<typename T, size_t N>
	constexpr size_t countof(const T (&)[N])
	{
		return N;
	}
	
	class StackObject
	{
	public:
		enum ObjectType
		{
			Object,
			Structure,
		};
		
	private:
		ObjectType type;
		
	public:
		StackObject(ObjectType type, StackObject* parent = nullptr)
		: type(type)
		{
		}
		
		virtual ~StackObject() = default;
		
		ObjectType getType() const { return type; }
		
		virtual void print(raw_ostream& os) const = 0;
		void dump() const
		{
			auto& stream = errs();
			print(stream);
			stream << '\n';
		}
	};
	
	class ObjectStackObject : public StackObject
	{
		Value& offset;
		
		static void getCastTypes(CastInst* cast, SmallPtrSetImpl<Type*>& types)
		{
			for (User* user : cast->users())
			{
				if (auto load = dyn_cast<LoadInst>(user))
				{
					auto loadType = load->getType();
					types.insert(loadType);
					
					if (loadType->isIntegerTy())
					{
						// see if that load is casted into something else
						for (User* loadUser : load->users())
						{
							if (auto subcast = dyn_cast<CastInst>(loadUser))
							if (subcast->getOpcode() == CastInst::IntToPtr)
							{
								SmallPtrSet<Type*, 2> castTypes;
								getCastTypes(subcast, castTypes);
								
								for (Type* t : castTypes)
								{
									types.insert(t->getPointerTo());
								}
							}
						}
					}
				}
				else if (auto store = dyn_cast<StoreInst>(user))
				{
					types.insert(store->getValueOperand()->getType());
				}
			}
		}
		
	public:
		static bool classof(const StackObject* obj)
		{
			return obj->getType() == Object;
		}
		
		ObjectStackObject(Value& offset, StackObject& parent)
		: StackObject(Object, &parent), offset(offset)
		{
		}
		
		Value* getOffsetValue() const { return &offset; }
		
		void getUnionTypes(SmallPtrSetImpl<Type*>& types) const
		{
			//
			// The offset may be used as:
			//
			// * an int2ptr cast operand leading to load/store instructions;
			// * a call argument;
			// * the value operand of a store instruction;
			// * an offset base to something else (we ignore that case here though).
			//
			// Only int2ptr -> load/store are useful to determine the type at an offset (at least until we have typed
			// function parameters). However, if we only see another use, we can determine that there's *at least
			// something* there; so default to void*.
			//
			
			size_t initialSize = types.size();
			for (User* offsetUser : offset.users())
			{
				if (auto cast = dyn_cast<CastInst>(offsetUser))
				{
					getCastTypes(cast, types);
				}
				else if (!isa<StoreInst>(offsetUser) && !isa<CallInst>(offsetUser))
				{
					assert(isa<BinaryOperator>(offsetUser) || isa<PHINode>(offsetUser));
				}
			}
			
			if (types.size() == initialSize)
			{
				// If there's no access, assume that there's at least a byte there.
				types.insert(Type::getVoidTy(offset.getContext()));
			}
		}
		
		virtual void print(raw_ostream& os) const override
		{
			os << '(';
			SmallPtrSet<Type*, 1> types;
			getUnionTypes(types);
			auto iter = types.begin();
			auto end = types.end();
			if (iter != end)
			{
				(*iter)->print(os);
				for (++iter; iter != end; ++iter)
				{
					os << ", ";
					(*iter)->print(os);
				}
			}
			os << ')';
		}
	};
	
	class StructureStackObject : public StackObject
	{
	public:
		struct StructureField
		{
			int64_t offset;
			unique_ptr<StackObject> object;
			
			StructureField(int64_t offset, unique_ptr<StackObject> object)
			: offset(offset), object(move(object))
			{
			}
			
			StructureField(int64_t offset, StackObject* object)
			: offset(offset), object(object)
			{
			}
			
			void print(raw_ostream& os) const
			{
				os << offset << ": ";
				object->print(os);
			}
		};
		
	private:
		vector<StructureField> fields;
		
	public:
		static bool classof(const StackObject* obj)
		{
			return obj->getType() == Structure;
		}
		
		StructureStackObject(StackObject* parent = nullptr)
		: StackObject(Structure, parent)
		{
		}
		
		auto begin() { return fields.begin(); }
		auto end() { return fields.end(); }
		auto begin() const { return fields.begin(); }
		auto end() const { return fields.end(); }
		
		size_t size() const { return fields.size(); }
		
		template<typename... Args>
		void insert(decltype(fields)::iterator position, Args&&... args)
		{
			fields.emplace(position, std::forward<Args>(args)...);
		}
		
		template<typename... Args>
		void insert(Args&&... args)
		{
			insert(end(), std::forward<Args>(args)...);
		}
		
		virtual void print(raw_ostream& os) const override
		{
			os << '{';
			auto iter = begin();
			if (iter != end())
			{
				iter->print(os);
				for (++iter; iter != end(); ++iter)
				{
					os << ", ";
					iter->print(os);
				}
			}
			os << '}';
		}
	};
	
	class OverlappingTypedAccesses
	{
	public:
		struct TypedAccess
		{
			int64_t offset;
			const StackObject* object;
			Type* type;
			
			TypedAccess(int64_t offset, const StackObject* object, Type* type)
			: offset(offset), object(object), type(type)
			{
			}
			
			uint64_t size(const DataLayout& dl) const
			{
				return type->isVoidTy() ? 0 : dl.getTypeStoreSize(type);
			}
			
			int64_t endOffset(const DataLayout& dl) const
			{
				return offset + static_cast<int64_t>(size(dl));
			}
		};
		
	private:
		static unsigned getTypePriority(Type* t)
		{
			static constexpr unsigned typePriority[] = {
				[Type::ArrayTyID] = 5,
				[Type::StructTyID] = 4,
				[Type::PointerTyID] = 3,
				[Type::FloatTyID] = 2,
				[Type::IntegerTyID] = 1,
			};
			
			auto id = t->getTypeID();
			if (id >= countof(typePriority))
			{
				return 0;
			}
			return typePriority[id];
		}
		
		const DataLayout& dl;
		vector<TypedAccess> accesses;
		
		template<typename T>
		void pad(LLVMContext& ctx, size_t difference, T outputIter) const
		{
			if (difference > 16)
			{
				ArrayType* int64Padding = ArrayType::get(Type::getInt64Ty(ctx), difference / 8);
				difference -= int64Padding->getNumElements() * 8;
				*outputIter = int64Padding;
				++outputIter;
			}
			
			for (unsigned i = 8; i > 0 && difference > 0; i /= 2)
			{
				if (difference >= i)
				{
					difference -= i;
					*outputIter = Type::getIntNTy(ctx, i * 8);
					++outputIter;
				}
			}
		}
		
	public:
		OverlappingTypedAccesses(const DataLayout& dl)
		: dl(dl)
		{
		}
		
		int64_t endOffset() const
		{
			if (accesses.size() == 0)
			{
				return 0;
			}
			return accesses.back().endOffset(dl);
		}
		
		bool insert(int64_t offset, const StackObject* object, Type* type)
		{
			if (accesses.size() != 0 && accesses.back().endOffset(dl) <= offset)
			{
				// not overlapping
				return false;
			}
			
			accesses.emplace_back(offset, object, type);
			return true;
		}
		
		bool empty() const
		{
			return accesses.empty();
		}
		
		void clear()
		{
			accesses.clear();
		}
		
		auto begin() { return accesses.begin(); }
		auto end() { return accesses.end(); }
		auto begin() const { return accesses.begin(); }
		auto end() const { return accesses.end(); }
		
		// returns the number of useful fields in outputType
		size_t reduce(LLVMContext& ctx, Type*& outputType, unordered_map<const StackObject*, int>& gepIndices) const
		{
			outputType = nullptr;
			gepIndices.clear();
			
			// No possible overlap
			if (accesses.size() == 0)
			{
				assert(false);
				outputType = nullptr;
				return 0;
			}
			else if (accesses.size() == 1)
			{
				outputType = accesses.front().type;
				return 1;
			}
			
			// Harder case: overlaps.
			// It is necessary that we can get a pointer to the beginning of the object. For instance:
			// +---------------+
			// 0|1|2|3|4|5|6|7|8
			// |--A:4--|--B:4--|
			// |.....|C:2|.....|
			// +---------------+
			// This needs to be represented as a structure where it's possible to get an offset to byte 0
			// (for object A), byte 3 (for object C) and byte 4 (for object B). This is satisfied by a struct such as
			// { [4 x i8], i32 }: a GEP to byte 0 is casted to an i32* for A, one to byte 3 is casted to an i16* for C,
			// and B has its own field. (An equivalent representation could be {i8, i8, i8, i8, i32}.)
			
			auto sortedAccesses = accesses;
			sort(sortedAccesses.begin(), sortedAccesses.end(), [&](const TypedAccess& a, const TypedAccess& b)
			{
				if (a.offset > b.offset)
				{
					return true;
				}
				
				if (a.offset < b.offset)
				{
					return false;
				}
				
				auto aSize = dl.getTypeStoreSize(a.type);
				auto bSize = dl.getTypeStoreSize(b.type);
				if (aSize > bSize)
				{
					return true;
				}
				if (aSize < bSize)
				{
					return false;
				}
				
				return getTypePriority(a.type) > getTypePriority(b.type);
			});
			
			size_t fieldCount = 1;
			deque<Type*> structBody;
			
			// The first type after sorting is always intact, the rest is broken up ugly.
			auto iter = sortedAccesses.begin();
			structBody.push_back(iter->type);
			gepIndices[iter->object] = -1;
			
			int64_t startOffset = iter->offset;
			int64_t endOffset = iter->endOffset(dl);
			for (++iter; iter != sortedAccesses.end(); ++iter)
			{
				int64_t iterFront = iter->offset;
				int64_t frontDifference = startOffset - iterFront;
				if (frontDifference > 0)
				{
					pad(ctx, static_cast<uint64_t>(frontDifference), front_inserter(structBody));
					startOffset = iterFront;
					fieldCount++;
				}
				
				int64_t iterEnd = iter->endOffset(dl);
				int64_t backDifference = iterEnd - endOffset;
				if (backDifference > 0)
				{
					pad(ctx, static_cast<uint64_t>(backDifference), back_inserter(structBody));
					endOffset = iterEnd;
				}
				
				gepIndices[iter->object] = -static_cast<int>(structBody.size());
			}
			
			if (fieldCount == 1)
			{
				// just return the only element in this case
				outputType = structBody[0];
				gepIndices.clear();
			}
			else
			{
				// needs contiguous storage for ArrayRef
				SmallVector<Type*, 4> body(structBody.begin(), structBody.end());
				outputType = StructType::get(ctx, body, true);
				for (auto& pair : gepIndices)
				{
					pair.second += structBody.size();
				}
			}
			return fieldCount;
		}
	};
	
	class GepLink
	{
		GepLink* parent;
		Value* index;
		Type* expectedType;
		
	public:
		GepLink()
		: parent(nullptr), index(nullptr), expectedType(nullptr)
		{
		}
		
		void setIndex(NOT_NULL(Value) index, NOT_NULL(Type) expectedType)
		{
			this->index = index;
			this->expectedType = expectedType;
		}
		
		void setParent(GepLink* parent)
		{
			assert(this->parent == nullptr);
			this->parent = parent;
		}
		
		GepLink* getParent() { return parent; }
		Value* getIndex() { return index; }
		Type* getExpectedType() { return expectedType; }
		
		vector<GepLink> toVector()
		{
			vector<GepLink> result;
			for (auto iter = this; iter != nullptr; iter = iter->parent)
			{
				result.push_back(*iter);
			}
			reverse(result.begin(), result.end());
			return result;
		}
	};
	
	Value* increment(Value* base)
	{
		if (auto constant = dyn_cast<ConstantInt>(base))
		{
			auto next = constant->getLimitedValue() + 1;
			return ConstantInt::get(constant->getType(), next);
		}
		else if (auto inst = dyn_cast<Instruction>(base))
		{
			auto one = ConstantInt::get(inst->getType(), 1);
			auto incremented = BinaryOperator::Create(BinaryOperator::Add, inst, one);
			incremented->insertAfter(inst);
			return incremented;
		}
		else
		{
			llvm_unreachable("not implemented");
		}
	}
	
	class LlvmStackFrame
	{
		
		LLVMContext& ctx;
		const DataLayout& dl;
		
		deque<GepLink> links;
		unordered_map<const StackObject*, GepLink*> linkMap;
		unordered_map<const StackObject*, Type*> typeMap;
		deque<const ObjectStackObject*> allObjects;
		
		LlvmStackFrame(LLVMContext& ctx, const DataLayout& dl)
		: ctx(ctx), dl(dl)
		{
		}
		
		GepLink* createLink()
		{
			links.emplace_back();
			return &links.back();
		}
		
		GepLink* linkFor(const StackObject* value)
		{
			GepLink*& result = linkMap[value];
			if (result == nullptr)
			{
				result = createLink();
			}
			return result;
		}
		
		Type* reduceStructField(OverlappingTypedAccesses& typedAccesses, GepLink* parentLink, uint64_t index)
		{
			Type* resultType;
			unordered_map<const StackObject*, int> gep;
			auto structFieldCount = typedAccesses.reduce(ctx, resultType, gep);
			
			if (structFieldCount == 0)
			{
				assert(false);
				return nullptr;
			}
			
			Type* i32 = Type::getInt32Ty(ctx);
			auto linkIndex = ConstantInt::get(i32, index);
			if (structFieldCount == 1)
			{
				for (const auto& access : typedAccesses)
				{
					auto fieldLink = linkFor(access.object);
					fieldLink->setIndex(linkIndex, access.type);
					fieldLink->setParent(parentLink);
				}
			}
			else
			{
				auto structureLink = createLink();
				structureLink->setParent(parentLink);
				structureLink->setIndex(linkIndex, resultType);
				
				for (const auto& access : typedAccesses)
				{
					auto iter = gep.find(access.object);
					if (iter == gep.end())
					{
						assert(false);
						return nullptr;
					}
					auto fieldLink = linkFor(access.object);
					fieldLink->setIndex(ConstantInt::get(i32, iter->second), access.type);
					fieldLink->setParent(structureLink);
				}
			}
			
			return resultType;
		}
		
		bool representObject(const ObjectStackObject* object)
		{
			SmallPtrSet<Type*, 4> types;
			object->getUnionTypes(types);
			
			OverlappingTypedAccesses typedAccesses(dl);
			for (Type* type : types)
			{
				if (!typedAccesses.insert(0, object, type))
				{
					return false;
				}
			}
			
			Type* resultType = nullptr;
			unordered_map<const StackObject*, int> gep;
			auto count = typedAccesses.reduce(ctx, resultType, gep);
			if (count != 1)
			{
				return false;
			}
			
			auto& typeOut = typeMap[object];
			assert(typeOut == nullptr);
			typeOut = resultType;
			allObjects.push_back(object);
			return true;
		}
		
		bool representObject(const StructureStackObject* object)
		{
			GepLink* thisLink = linkFor(object);
			vector<Type*> fieldTypes;
			OverlappingTypedAccesses typedAccesses(dl);
			
			for (const auto& field : *object)
			{
				StackObject* fieldObject = field.object.get();
				if (!representObject(fieldObject))
				{
					// bail out if field can't be represented
					return false;
				}
				
				Type* fieldType = typeMap[field.object.get()];
				if (typedAccesses.insert(field.offset, fieldObject, fieldType))
				{
					// continue until accesses no longer overlap
					continue;
				}
				
				if (Type* result = reduceStructField(typedAccesses, thisLink, fieldTypes.size()))
				{
					if (!result->isVoidTy())
					{
						// Don't insert void as a struct member. The GepLink* will just end up referring to the
						// next object, which is most likely to be either padding (which would be correct) or the end of
						// the structure.
						fieldTypes.push_back(result);
					}
					
					long long padding = field.offset - typedAccesses.endOffset();
					if (padding > 0)
					{
						Type* i8 = Type::getInt8Ty(ctx);
						Type* padArray = ArrayType::get(i8, static_cast<uint64_t>(padding));
						fieldTypes.push_back(padArray);
					}
					
					typedAccesses.clear();
					typedAccesses.insert(field.offset, field.object.get(), fieldType);
				}
				else
				{
					return false;
				}
			}
			
			if (!typedAccesses.empty())
			{
				if (Type* result = reduceStructField(typedAccesses, thisLink, fieldTypes.size()))
				{
					if (!result->isVoidTy())
					{
						fieldTypes.push_back(result);
					}
				}
				else
				{
					return false;
				}
			}
			
			Type* resultType = StructType::get(ctx, fieldTypes, true);
			auto& resultOut = typeMap[object];
			assert(resultOut == nullptr);
			resultOut = resultType;
			return true;
		}
		
		bool representObject(StackObject* object)
		{
			if (auto obj = dyn_cast<ObjectStackObject>(object))
			{
				return representObject(obj);
			}
			else if (auto structure = dyn_cast<StructureStackObject>(object))
			{
				return representObject(structure);
			}
			else
			{
				return false;
			}
		}
		
	public:
		static unique_ptr<LlvmStackFrame> representObject(LLVMContext& ctx, const DataLayout& dl, const StructureStackObject& object)
		{
			unique_ptr<LlvmStackFrame> frame(new LlvmStackFrame(ctx, dl));
			if (frame->representObject(&object))
			{
				Type* rootType = frame->getNaiveType(object);
				frame->linkFor(&object)->setIndex(ConstantInt::get(Type::getInt64Ty(ctx), 0), rootType);
				return frame;
			}
			return nullptr;
		}
		
		const deque<const ObjectStackObject*>& getAllObjects() const { return allObjects; }
		
		Type* getNaiveType(const StackObject& object) const
		{
			auto iter = typeMap.find(&object);
			if (iter == typeMap.end())
			{
				return nullptr;
			}
			return iter->second;
		}

		Value* getPointerToObject(const ObjectStackObject& object, Value* basePointer, Instruction* insertionPoint) const
		{
			auto linkMapIter = linkMap.find(&object);
			if (linkMapIter == linkMap.end())
			{
				return nullptr;
			}
			
			ConstantInt* zero = ConstantInt::get(Type::getInt64Ty(ctx), 0);
			Value* result = basePointer;
			SmallVector<Value*, 4> gepIndices;
			
			auto vectorOfLinks = linkMapIter->second->toVector();
			// If we're seeking a void element, we need to adjust the GEP to get the element after it. This is already
			// done at representation time unless the item we seek is the last item of the structure.
			if (vectorOfLinks.back().getExpectedType()->isVoidTy())
			{
				Type* voidTy = vectorOfLinks.back().getExpectedType();
				for (size_t size = vectorOfLinks.size(); size > 1; --size)
				{
					GepLink& parentLink = vectorOfLinks[size - 2];
					GepLink& currentLink = vectorOfLinks[size - 1];
					
					// The index can only refer to a void field if it is constant.
					// Otherwise we're probably indexing into an array or something.
					if (auto constant = dyn_cast<ConstantInt>(currentLink.getIndex()))
					{
						auto parentType = parentLink.getExpectedType();
						bool shouldIncrementIndex = false;
						if (auto parentStruct = dyn_cast<StructType>(parentType))
						{
							if (parentStruct->getNumElements() == constant->getLimitedValue())
							{
								shouldIncrementIndex = true;
							}
							else
							{
								// stop after this iteration
								size = 1;
							}
						}
						else
						{
							shouldIncrementIndex = isa<PointerType>(parentType);
							// no point in looping any further
							size = 1;
						}
						
						if (shouldIncrementIndex)
						{
							parentLink.setIndex(increment(parentLink.getIndex()), voidTy);
							vectorOfLinks.pop_back();
						}
					}
					else
					{
						// stop after this iteration
						size = 1;
					}
				}
			}
			
			for (GepLink& link : vectorOfLinks)
			{
				gepIndices.push_back(link.getIndex());
				Type* expected = link.getExpectedType();
				Type* actual = GetElementPtrInst::getIndexedType(result->getType(), gepIndices);
				if (expected != actual && !expected->isVoidTy())
				{
					result = GetElementPtrInst::Create(nullptr, result, gepIndices, "", insertionPoint);
					result = CastInst::Create(CastInst::BitCast, result, expected->getPointerTo(), "", insertionPoint);
					gepIndices = { zero };
				}
			}
			
			if (gepIndices.size() > 1)
			{
				result = GetElementPtrInst::Create(nullptr, result, gepIndices, "", insertionPoint);
			}
			
			return result;
		}
	};
	
	// This pass needs to run AFTER argument recovery.
	struct IdentifyLocals final : public ModulePass
	{
		static char ID;
		const DataLayout* dl = nullptr;
		bool changed = false;
		
		IdentifyLocals() : ModulePass(ID)
		{
		}
		
		virtual const char* getPassName() const override
		{
			return "Identify locals";
		}
		
		Argument* getStackPointer(Function& fn)
		{
			ConstantInt* stackPointerIndex = md::getStackPointerArgument(fn);
			if (stackPointerIndex == nullptr)
			{
				return nullptr;
			}
			
			auto arg = fn.arg_begin();
			advance(arg, stackPointerIndex->getLimitedValue());
			return static_cast<Argument*>(arg);
		}
		
		bool analyzeObject(Value& base, bool& hasCastInst, map<int64_t, Instruction*>& constantOffsets, map<int64_t, Instruction*>& variableOffsetStrides)
		{
			hasCastInst = false;
			for (User* user : base.users())
			{
				if (auto binOp = dyn_cast<BinaryOperator>(user))
				{
					if (binOp->getOpcode() != BinaryOperator::Add)
					{
						return false;
					}
					
					Value* right = binOp->getOperand(binOp->getOperand(0) == &base ? 1 : 0);
					if (auto constant = dyn_cast<ConstantInt>(right))
					{
						constantOffsets.insert({constant->getLimitedValue(), binOp});
					}
					else
					{
						// non-constant offset
						// IMPLEMENT ME
						return false;
					}
				}
				else if (auto castInst = dyn_cast<CastInst>(user))
				{
					hasCastInst |= castInst->getOpcode() == CastInst::IntToPtr;
				}
			}
			return true;
		}
		
		unique_ptr<StackObject> readObject(Value& base, StackObject* parent)
		{
			//
			// readObject accepts a "base pointer". A base pointer is an SSA value that modifies the stack pointer.
			// Examples would be the stack pointer itself, "sp+N" (for a constant N), "(sp+N)+v" (for a non-constant v).
			// This base pointer is expected to:
			//
			// * have variable offsets added to it (making it an array);
			// * have constant offsets added to it (making it a struct);
			// * be loaded from/stored to (giving it a specific type).
			//
			// It's likely that a base pointer is used in multiple ways. In this case, the following rules
			// disambiguate what to do with it:
			//
			// * if it's offset by a variable, automatically treat it as an array;
			// * if it's only offset by constant values, treat it as a structure.
			//
			// The rationale for arrays is that it's less likely that the SSA form will allow a non-array pointer value
			// to be offset sometimes by a constant and sometimes by a value. If you have a
			// `struct { int x, y; int z[20] };` on the stack, then accesses to `z` will look like "(sp+8)+N"
			// (or "(sp+8)+(N*4)"), where (sp+8) will be considered the array.
			//
			// This may misrepresent structures that begin with an array, however.
			//
			// Notice how we don't do anything with loads/stores. That's because they require to be casted to a
			// pointer type first. Casts become a new base value and these are usually only loaded from/stored to. In
			// practice, we only generate arrays and struct from this function.
			//
			
			bool hasCastInst = false;
			map<int64_t, Instruction*> constantOffsets;
			map<int64_t, Instruction*> variableOffsetsStrides;
			if (!analyzeObject(base, hasCastInst, constantOffsets, variableOffsetsStrides))
			{
				return nullptr;
			}
			
			if (variableOffsetsStrides.size() > 0)
			{
				// This should be an array.
				// (IMPLEMENT ME)
				return nullptr;
			}
			else if (constantOffsets.size() > 0)
			{
				// Since this runs after argument recovery, offsets should uniformly be either positive or negative.
				auto front = constantOffsets.begin()->first;
				auto back = constantOffsets.rbegin()->first;
				assert(front == 0 || back == 0 || signbit(front) == signbit(back));
				(void) back;
				
				unique_ptr<StructureStackObject> structure(new StructureStackObject(parent));
				if (hasCastInst)
				{
					structure->insert(0, new ObjectStackObject(base, *structure));
				}
				
				for (const auto& pair : constantOffsets)
				{
					if (auto type = readObject(*pair.second, structure.get()))
					{
						int64_t offset = pair.first - front;
						structure->insert(offset, move(type));
					}
				}
				return move(structure);
			}
			else
			{
				return unique_ptr<StackObject>(new ObjectStackObject(base, *parent));
			}
		}
		
		virtual bool doInitialization(Module& m) override
		{
			dl = &m.getDataLayout();
			return ModulePass::doInitialization(m);
		}
		
		virtual bool runOnModule(Module& m) override
		{
			auto& functionList = m.getFunctionList();
			
			// copy function list because we're about to modify it
			vector<Function*> functions;
			functions.reserve(functionList.size());
			for (Function& fn : functionList)
			{
				functions.push_back(&fn);
			}
			
			changed = false;
			for (Function* fn : functions)
			{
				tryToCreateStackFrame(*fn);
				tryToRemoveStackArgument(*fn);
			}
			
			return changed;
		}
		
		void tryToRemoveStackArgument(Function& fn)
		{
			assert(!fn.hasAddressTaken());
			
			if (ConstantInt* spArgIndex = md::getStackPointerArgument(fn))
			{
				size_t index = spArgIndex->getLimitedValue();
				auto arg = fn.arg_begin();
				advance(arg, index);
				if (arg->getNumUses() == 0)
				{
					// create function type without argument at spArgIndex
					FunctionType* oldFnType = fn.getFunctionType();
					SmallVector<Type*, 8> parameters(oldFnType->param_begin(), oldFnType->param_end());
					parameters.erase(parameters.begin() + index);
					FunctionType* newFnType = FunctionType::get(oldFnType->getReturnType(), parameters, oldFnType->isVarArg());
					
					// create new function, copy attributes and metadata
					Function* newFunc = Function::Create(newFnType, fn.getLinkage());
					newFunc->copyAttributesFrom(&fn);
					fn.getParent()->getFunctionList().insert(fn.getIterator(), newFunc);
					newFunc->takeName(&fn);
					md::copy(fn, *newFunc);
					md::removeStackPointerArgument(*newFunc);
					
					// copy function over
					newFunc->getBasicBlockList().splice(newFunc->begin(), fn.getBasicBlockList());
					
					// change argument references
					SmallVector<Argument*, 8> oldArgs;
					for (Argument& arg : fn.args())
					{
						oldArgs.push_back(&arg);
					}
					oldArgs.erase(oldArgs.begin() + index);
					
					SmallVector<Argument*, 8> newArgs;
					for (Argument& arg : newFunc->args())
					{
						newArgs.push_back(&arg);
					}
					
					for (size_t i = 0; i < newArgs.size(); ++i)
					{
						oldArgs[i]->replaceAllUsesWith(newArgs[i]);
						newArgs[i]->takeName(oldArgs[i]);
					}
					
					// update call sites
					while (!fn.user_empty())
					{
						auto user = *fn.user_begin();
						if (auto call = dyn_cast<CallInst>(user))
						{
							SmallVector<Value*, 8> args;
							for (unsigned i = 0; i < call->getNumArgOperands(); ++i)
							{
								if (i != index)
								{
									args.push_back(call->getArgOperand(i));
								}
							}
							
							auto newCall = CallInst::Create(newFunc, args, "", call);
							newCall->takeName(call);
							call->replaceAllUsesWith(newCall);
							call->eraseFromParent();
						}
						else
						{
							assert(false);
							return;
						}
					}
					
					fn.eraseFromParent();
					changed = true;
				}
			}
		}
		
		void tryToCreateStackFrame(Function& fn)
		{
			if (Argument* stackPointer = getStackPointer(fn))
			if (auto root = readObject(*stackPointer, nullptr))
			if (auto llvmFrame = LlvmStackFrame::representObject(fn.getContext(), *dl, cast<StructureStackObject>(*root)))
			{
				auto allocaInsert = static_cast<Instruction*>(fn.getEntryBlock().getFirstInsertionPt());
				Type* naiveType = llvmFrame->getNaiveType(*root);
				AllocaInst* stackFrame = new AllocaInst(naiveType, "stackframe", allocaInsert);
				md::setStackFrame(*stackFrame);
				for (auto object : llvmFrame->getAllObjects())
				{
					Value* offsetInstruction = object->getOffsetValue();
					Instruction* insertionPoint = dyn_cast<Instruction>(offsetInstruction);
					
					Value* pointer = llvmFrame->getPointerToObject(*object, stackFrame, insertionPoint);
					auto ptr2int = CastInst::Create(CastInst::PtrToInt, pointer, offsetInstruction->getType(), "", insertionPoint);
					offsetInstruction->replaceAllUsesWith(ptr2int);
					if (auto inst = dyn_cast<Instruction>(offsetInstruction))
					{
						inst->dropAllReferences();
						inst->eraseFromParent();
					}
				}
				changed = true;
			}
		}
	};
	
	char IdentifyLocals::ID = 0;
	RegisterPass<IdentifyLocals> identifyLocals("recoverstackframe", "Identify local variables");
}
