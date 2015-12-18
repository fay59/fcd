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
#include <vector>

using namespace llvm;
using namespace llvm::PatternMatch;
using namespace std;

namespace
{
	struct StackObject
	{
		enum ObjectType
		{
			Object,
			Array,
			StructField,
		};
		
		intptr_t offsetFromParent;
		
		union
		{
			struct
			{
				Type* objectType;
				StackObject* objectNextInterpretation;
			};
			
			struct
			{
				StackObject* arrayElementType;
				uintptr_t arrayMinKnownCount;
			};
			
			struct
			{
				StackObject* structFieldType;
				StackObject* structNextField;
			};
		};
		
		ObjectType type;
		
		StackObject(ObjectType type)
		: offsetFromParent(0), objectType(nullptr), objectNextInterpretation(nullptr), type(type)
		{
		}
		
		void print(raw_ostream& os) const
		{
			if (type == Object)
			{
				os << '(';
				objectType->print(os);
				for (auto item = objectNextInterpretation; item != nullptr; item = item->objectNextInterpretation)
				{
					os << ", ";
					item->objectType->print(os);
				}
				os << ')';
			}
			else if (type == Array)
			{
				os << '[' << arrayMinKnownCount << " x ";
				arrayElementType->print(os);
				os << ']';
			}
			else if (type == StructField)
			{
				os << '{';
				os << offsetFromParent << ": ";
				structFieldType->print(os);
				for (auto item = structNextField; item != nullptr; item = item->structNextField)
				{
					os << ", " << item->offsetFromParent << ": ";
					item->structFieldType->print(os);
				}
				os << '}';
			}
			else
			{
				llvm_unreachable("unknown type");
			}
		}
		
		void dump() const
		{
			auto& os = errs();
			print(os);
			os << '\n';
		}
	};
	
	Type* getLoadStoreType(Instruction* inst)
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
	
	void getPointerCastTypes(CastInst* inst, SmallPtrSetImpl<Type*>& types)
	{
		for (User* user : inst->users())
		{
			if (auto type = getLoadStoreType(dyn_cast<Instruction>(user)))
			{
				types.insert(type);
			}
		}
	}
	
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
		
		bool analyzeObject(Value& base, SmallPtrSetImpl<Type*>& readTypes, map<int64_t, Instruction*>& constantOffsets, map<int64_t, Instruction*>& variableOffsetStrides)
		{
			for (User* user : base.users())
			{
				if (auto castInst = dyn_cast<CastInst>(user))
				{
					getPointerCastTypes(castInst, readTypes);
				}
				else if (auto binOp = dyn_cast<BinaryOperator>(user))
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
						llvm_unreachable("implement me");
					}
				}
			}
			return true;
		}
		
		StackObject* readObject(DumbAllocator& pool, Value& base)
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
			
			SmallPtrSet<Type*, 1> readTypes;
			map<int64_t, Instruction*> constantOffsets;
			map<int64_t, Instruction*> variableOffsetsStrides;
			if (!analyzeObject(base, readTypes, constantOffsets, variableOffsetsStrides))
			{
				return nullptr;
			}
			
			StackObject* offset0 = nullptr;
			if (readTypes.size() > 0)
			{
				auto iter = readTypes.begin();
				offset0 = pool.allocate<StackObject>(StackObject::Object);
				offset0->objectType = *iter;
				
				auto currentObject = offset0;
				for (++iter; iter != readTypes.end(); ++iter)
				{
					auto next = pool.allocate<StackObject>(StackObject::Object);
					next->objectType = *iter;
					currentObject->objectNextInterpretation = next;
					currentObject = next;
				}
			}
			
			if (variableOffsetsStrides.size() > 0)
			{
				// This should be an array.
				llvm_unreachable("not implemented");
			}
			else
			{
				// This will be a structure, possibly with offset0 as the first field.
				if (offset0 != nullptr)
				{
					constantOffsets.insert({0, nullptr});
				}
				
				if (constantOffsets.size() > 0)
				{
					// Since this runs after argument recovery, every offset should be either positive or negative.
					auto front = constantOffsets.begin()->first;
					auto back = constantOffsets.rbegin()->first;
					assert(front == 0 || back == 0 || signbit(front) == signbit(back));
					
					intptr_t padTo = 0;
					StackObject* firstItem = nullptr;
					StackObject* lastItem = nullptr;
					for (const auto& pair : constantOffsets)
					{
						if (auto child = pair.second == nullptr ? offset0 : readObject(pool, *pair.second))
						{
							child->offsetFromParent = pair.first;
							
							StackObject* result = pool.allocate<StackObject>(StackObject::StructField);
							result->structFieldType = child;
							if (lastItem == nullptr)
							{
								firstItem = result;
								lastItem = result;
							}
							else
							{
								lastItem->structNextField = result;
								lastItem = result;
							}
						}
						else
						{
							padTo = pair.first < 0
								? min<intptr_t>(padTo, pair.first)
								: max<intptr_t>(padTo, pair.first);
						}
					}
					
					if (padTo != 0)
					{
						StackObject* result = pool.allocate<StackObject>(StackObject::StructField);
						StackObject* padObject = pool.allocate<StackObject>(StackObject::Object);
						padObject->objectType = Type::getVoidTy(base.getContext());
						result->structFieldType = padObject;
						result->offsetFromParent = padTo;
						if (lastItem == nullptr)
						{
							firstItem = result;
						}
						else
						{
							lastItem->structNextField = result;
						}
					}
					return firstItem;
				}
			}
			return offset0;
		}
		
		virtual bool doInitialization(Module& m) override
		{
			dl = &m.getDataLayout();
			return FunctionPass::doInitialization(m);
		}
		
		virtual bool runOnFunction(Function& fn) override
		{
			Argument* stackPointer = getStackPointer(fn);
			if (stackPointer == nullptr)
			{
				return false;
			}
			
			DumbAllocator typeAllocator;
			errs() << fn.getName() << ": ";
			if (StackObject* root = readObject(typeAllocator, *stackPointer))
			{
				root->dump();
			}
			else
			{
				errs() << '\n';
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
