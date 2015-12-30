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
#include "llvm_warnings.h"
#include "metadata.h"
#include "passes.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/PatternMatch.h>
SILENCE_LLVM_WARNINGS_END()

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
		StackObject* parent;
		ObjectType type;
		
	public:
		StackObject(ObjectType type, StackObject* parent = nullptr)
		: parent(nullptr), type(type)
		{
		}
		
		virtual ~StackObject() = default;
		
		ObjectType getType() const { return type; }
		
		virtual void print(raw_ostream& os) const = 0;
		void dump() const { print(errs()); }
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
					types.insert(load->getType());
					
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
			
			bool defaultsToVoid = false;
			size_t initialSize = types.size();
			for (User* offsetUser : offset.users())
			{
				if (auto cast = dyn_cast<CastInst>(offsetUser))
				{
					getCastTypes(cast, types);
				}
				else if (isa<StoreInst>(offsetUser) || isa<CallInst>(offsetUser))
				{
					defaultsToVoid = true;
				}
				else
				{
					assert(isa<BinaryOperator>(offsetUser) || isa<PHINode>(offsetUser));
				}
			}
			
			if (types.size() == initialSize && defaultsToVoid)
			{
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
		
		struct TypedAccess
		{
			int64_t offset;
			const StackObject* object;
			Type* type;
			
			TypedAccess(int64_t offset, const StackObject* object, Type* type)
			: offset(offset), object(object), type(type)
			{
			}
			
			int64_t endOffset(const DataLayout& dl) const
			{
				return offset + dl.getTypeStoreSize(type);
			}
		};
		
		const DataLayout& dl;
		vector<TypedAccess> accesses;
		
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
		
		Type* reduce(LLVMContext& ctx) const
		{
			if (accesses.size() == 0)
			{
				return Type::getVoidTy(ctx);
			}
			
			auto iter = accesses.begin();
			auto offset = iter->offset;
			Type* currentType = iter->type;
			for (++iter; iter != accesses.end(); ++iter)
			{
				if (iter->offset != offset)
				{
					// as an oversimplification that we'll need to get rid of at some point, objects need to be aligned
					// on the same boundary
					return nullptr;
				}
				
				auto currentPriority = getTypePriority(currentType);
				auto thisPriority = getTypePriority(iter->type);
				if (currentPriority < thisPriority)
				{
					currentType = iter->type;
				}
				else if (currentPriority == thisPriority && dl.getTypeStoreSize(currentType) < dl.getTypeStoreSize(iter->type))
				{
					currentType = iter->type;
				}
			}
			
			return currentType;
		}
	};
			
	class LlvmStackFrame
	{
		struct GepLink
		{
			GepLink* parent;
			Value* index;
			
			GepLink(Value* index, GepLink* parent = nullptr)
			: parent(parent), index(index)
			{
			}
			
			void fill(vector<Value*>& indices) const
			{
				if (parent != nullptr)
				{
					parent->fill(indices);
				}
				indices.push_back(index);
			}
		};
		
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
		
		GepLink* linkFor(const StackObject* value, GepLink* parent, uint64_t index, Type* indexType = nullptr)
		{
			GepLink*& result = linkMap[value];
			if (result == nullptr)
			{
				if (indexType == nullptr)
				{
					// Structure indices need to be i32, pointer indices need to be i64. Sigh.
					indexType = Type::getInt32Ty(ctx);
				}
				Constant* constantIndex = ConstantInt::get(indexType, index);
				links.emplace_back(constantIndex, parent);
				result = &links.back();
			}
			else
			{
				assert(result->parent == parent);
			}
			return result;
		}
		
		bool representObject(const ObjectStackObject* object, GepLink* self)
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
			
			if (auto type = typedAccesses.reduce(ctx))
			{
				auto& typeOut = typeMap[object];
				assert(typeOut == nullptr);
				typeOut = type;
				allObjects.push_back(object);
				return true;
			}
			return false;
		}
		
		bool representObject(const StructureStackObject* object, GepLink* self)
		{
			Type* i8 = Type::getInt8Ty(ctx);
			Type* voidTy = Type::getVoidTy(ctx);
			
			SmallPtrSet<Type*, 1> typeSet;
			vector<Type*> fieldTypes;
			
			OverlappingTypedAccesses typedAccesses(dl);
			for (const auto& field : *object)
			{
				StackObject* fieldObject = field.object.get();
				if (!representObject(fieldObject, linkFor(fieldObject, self, fieldTypes.size())))
				{
					// bail out if field can't be represented or if it has multiple representations
					return false;
				}
				
				Type* representedType = typeMap[field.object.get()];
				if (!typedAccesses.insert(field.offset, field.object.get(), representedType))
				{
					if (auto type = typedAccesses.reduce(ctx))
					{
						if (type != voidTy)
						{
							fieldTypes.push_back(type);
						}
					}
					else
					{
						return false;
					}
					
					auto endOffset = typedAccesses.endOffset();
					if (field.offset > endOffset)
					{
						int64_t length = field.offset - endOffset;
						Type* padding = ArrayType::get(i8, static_cast<uint64_t>(length));
						fieldTypes.push_back(padding);
					}
					
					typedAccesses.clear();
					typedAccesses.insert(field.offset, field.object.get(), representedType);
				}
			}
			
			if (!typedAccesses.empty())
			{
				if (auto type = typedAccesses.reduce(ctx))
				{
					if (type != voidTy)
					{
						fieldTypes.push_back(type);
					}
				}
				else
				{
					return false;
				}
			}
			
			StructType* result = StructType::get(ctx, fieldTypes, true);
			auto& resultOut = typeMap[object];
			assert(resultOut == nullptr);
			resultOut = result;
			return true;
		}
		
		bool representObject(StackObject* object, GepLink* self)
		{
			if (auto obj = dyn_cast<ObjectStackObject>(object))
			{
				return representObject(obj, self);
			}
			else if (auto structure = dyn_cast<StructureStackObject>(object))
			{
				return representObject(structure, self);
			}
			else
			{
				return false;
			}
		}
		
	public:
		static unique_ptr<LlvmStackFrame> representObject(LLVMContext& ctx, const DataLayout& dl, const StructureStackObject& object)
		{
			object.dump();
			Type* i64 = Type::getInt64Ty(ctx);
			unique_ptr<LlvmStackFrame> frame(new LlvmStackFrame(ctx, dl));
			if (frame->representObject(&object, frame->linkFor(&object, nullptr, 0, i64)))
			{
				return frame;
			}
			return nullptr;
		}
		
		const deque<const ObjectStackObject*>& getAllObjects() const { return allObjects; }
		
		Type* getObjectType(const StackObject& object) const
		{
			auto iter = typeMap.find(&object);
			if (iter == typeMap.end())
			{
				return nullptr;
			}
			return iter->second;
		}

		bool fillOffsetsToObject(const ObjectStackObject& object, vector<Value*>& indices) const
		{
			auto iter = linkMap.find(&object);
			if (iter == linkMap.end())
			{
				return false;
			}
			iter->second->fill(indices);
			return true;
		}
	};
	
	// This pass needs to run AFTER argument recovery.
	struct IdentifyLocals : public FunctionPass
	{
		static char ID;
		const DataLayout* dl;
		
		IdentifyLocals() : FunctionPass(ID)
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
			return arg;
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
				// Since this runs after argument recovery, every offset should be either positive or negative.
				auto front = constantOffsets.begin()->first;
				auto back = constantOffsets.rbegin()->first;
				assert(front == 0 || back == 0 || signbit(front) == signbit(back));
				
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
			else if (hasCastInst)
			{
				return unique_ptr<StackObject>(new ObjectStackObject(base, *parent));
			}
			return nullptr;
		}
		
		virtual bool doInitialization(Module& m) override
		{
			dl = &m.getDataLayout();
			return FunctionPass::doInitialization(m);
		}
		
		virtual bool runOnFunction(Function& fn) override
		{
			if (Argument* stackPointer = getStackPointer(fn))
			if (auto root = readObject(*stackPointer, nullptr))
			if (auto llvmFrame = LlvmStackFrame::representObject(fn.getContext(), *dl, cast<StructureStackObject>(*root)))
			{
				auto allocaInsert = fn.getEntryBlock().getFirstInsertionPt();
				AllocaInst* stackFrame = new AllocaInst(llvmFrame->getObjectType(*root), "stackframe", allocaInsert);
				md::setStackFrame(*stackFrame);
				for (auto object : llvmFrame->getAllObjects())
				{
					vector<Value*> indices;
					llvmFrame->fillOffsetsToObject(*object, indices);
					
					Value* offsetInstruction = object->getOffsetValue();
					Instruction* insertionPoint = dyn_cast<Instruction>(offsetInstruction);
					if (insertionPoint == nullptr)
					{
						insertionPoint = stackFrame->getNextNode();
					}
					auto gep = GetElementPtrInst::Create(nullptr, stackFrame, indices, "", insertionPoint);
					auto ptr2int = CastInst::Create(CastInst::PtrToInt, gep, offsetInstruction->getType(), "", insertionPoint);
					offsetInstruction->replaceAllUsesWith(ptr2int);
				}
				return true;
			}
			
			return false;
		}
	};
	
	char IdentifyLocals::ID = 0;
	RegisterPass<IdentifyLocals> identifyLocals("--identify-locals", "Identify local variables", false, false);
}

FunctionPass* createIdentifyLocalsPass()
{
	return new IdentifyLocals;
}
