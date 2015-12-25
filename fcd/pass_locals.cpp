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
		CastInst& cast;
		
		static Type* getLoadStoreType(Instruction* inst)
		{
			if (auto load = dyn_cast_or_null<LoadInst>(inst))
			{
				return load->getType();
			}
			else if (auto store = dyn_cast_or_null<StoreInst>(inst))
			{
				return store->getValueOperand()->getType();
			}
			else
			{
				return nullptr;
			}
		}
		
	public:
		static bool classof(const StackObject* obj)
		{
			return obj->getType() == Object;
		}
		
		ObjectStackObject(CastInst& inst, StackObject& parent)
		: StackObject(Object, &parent), cast(inst)
		{
		}
		
		CastInst* getCast() const { return &cast; }
		
		void getUnionTypes(SmallPtrSetImpl<Type*>& types) const
		{
			for (User* user : cast.users())
			{
				if (auto type = getLoadStoreType(dyn_cast<Instruction>(user)))
				{
					types.insert(type);
				}
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
	
	class StructStackObject : public StackObject
	{
	public:
		struct StructField
		{
			int64_t offset;
			unique_ptr<StackObject> object;
			
			StructField(int64_t offset, unique_ptr<StackObject> object)
			: offset(offset), object(move(object))
			{
			}
			
			StructField(int64_t offset, StackObject* object)
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
		vector<StructField> fields;
		
	public:
		static bool classof(const StackObject* obj)
		{
			return obj->getType() == Structure;
		}
		
		StructStackObject(StackObject* parent = nullptr)
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
			SmallPtrSet<Type*, 1> type;
			object->getUnionTypes(type);
			if (type.size() == 1)
			{
				auto& typeOut = typeMap[object];
				assert(typeOut == nullptr);
				typeOut = *type.begin();
				allObjects.push_back(object);
				return true;
			}
			return false;
		}
		
		bool representObject(const StructStackObject* object, GepLink* self)
		{
			SmallPtrSet<Type*, 1> typeSet;
			vector<Type*> fieldTypes;
			
			uint64_t index = 0;
			Type* i8 = Type::getInt8Ty(ctx);
			int64_t lastOffset = 0;
			for (const auto& field : *object)
			{
				if (field.offset > lastOffset)
				{
					// add i8 array for padding
					int64_t length = field.offset - lastOffset;
					Type* padding = ArrayType::get(i8, static_cast<uint64_t>(length));
					fieldTypes.push_back(padding);
					index++;
				}
				else if (field.offset < lastOffset)
				{
					// there is overlapping and we don't support that at the moment
					return false;
				}
				
				typeSet.clear();
				StackObject* fieldObject = field.object.get();
				if (!representObject(fieldObject, linkFor(fieldObject, self, index)))
				{
					// bail out if field can't be represented or if it has multiple representations
					return false;
				}
				Type* objectType = typeMap[field.object.get()];
				
				// (it will eventually become relevant that this is a for loop, even though there's only one item)
				fieldTypes.push_back(objectType);
				lastOffset = field.offset + dl.getTypeStoreSize(objectType);
				index++;
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
			else if (auto structure = dyn_cast<StructStackObject>(object))
			{
				return representObject(structure, self);
			}
			else
			{
				return false;
			}
		}
		
	public:
		static unique_ptr<LlvmStackFrame> representObject(LLVMContext& ctx, const DataLayout& dl, const StructStackObject& object)
		{
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
		
		bool analyzeObject(Value& base, CastInst*& castedAs, map<int64_t, Instruction*>& constantOffsets, map<int64_t, Instruction*>& variableOffsetStrides)
		{
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
					if (castInst->getOpcode() == CastInst::IntToPtr)
					{
						castedAs = castInst;
					}
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
			
			CastInst* castedAs = nullptr;
			map<int64_t, Instruction*> constantOffsets;
			map<int64_t, Instruction*> variableOffsetsStrides;
			if (!analyzeObject(base, castedAs, constantOffsets, variableOffsetsStrides))
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
				
				unique_ptr<StructStackObject> structure(new StructStackObject(parent));
				if (castedAs != nullptr)
				{
					structure->insert(0, new ObjectStackObject(*castedAs, *structure));
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
			else if (castedAs != nullptr)
			{
				return unique_ptr<StackObject>(new ObjectStackObject(*castedAs, *parent));
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
			if (auto llvmFrame = LlvmStackFrame::representObject(fn.getContext(), *dl, cast<StructStackObject>(*root)))
			{
				auto insertionPoint = fn.getEntryBlock().getFirstInsertionPt();
				AllocaInst* stackFrame = new AllocaInst(llvmFrame->getObjectType(*root), "stackframe", insertionPoint);
				md::setStackFrame(*stackFrame);
				for (auto object : llvmFrame->getAllObjects())
				{
					vector<Value*> indices;
					llvmFrame->fillOffsetsToObject(*object, indices);
					
					CastInst* cast = object->getCast();
					auto gep = GetElementPtrInst::Create(nullptr, stackFrame, indices, "", cast);
					cast->replaceAllUsesWith(gep);
				}
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
