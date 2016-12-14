//
// pass_pointerdiscovery.cpp
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
#include "pointer_discovery.h"

#include <llvm/IR/Constants.h>

using namespace llvm;
using namespace std;

namespace
{
	void printFunctionSuffix(raw_ostream& os, Value& value)
	{
		const Function* func = nullptr;
		if (auto inst = dyn_cast<Instruction>(&value))
		if (auto block = inst->getParent())
		{
			func = block->getParent();
		}
		if (auto arg = dyn_cast<Argument>(&value))
		{
			func = arg->getParent();
		}
		
		if (func != nullptr)
		{
			os << " [" << func->getName() << "]";
		}
	}
	
	struct ValueTypeConstraint;
	typedef unordered_set<ValueTypeConstraint*> LinkedValues;
	
	struct ValueTypeConstraint
	{
		enum Type
		{
			Unset,
			// Don't care what it is (may be refined to any other type)
			Either,
			// At most one of `thisValue` and `otherValue` is a pointer; the other (or both) are integers.
			AtMostOnePointer,
			// We know that this is a pointer (final state)
			IsPointer,
			// We know that this is an integer (final state)
			IsInteger,
		};
		
		NOT_NULL(LinkedValues) sameTypeSet;
		Value& thisValue;
		Value* otherValue;
		Type type;
		
		ValueTypeConstraint(Type type, NOT_NULL(LinkedValues) sameTypeSet, Value& thisValue, Value* other = nullptr)
		: type(type), sameTypeSet(sameTypeSet), thisValue(thisValue), otherValue(other)
		{
			assert(type != Unset);
			// There should only have an `other` parameter with the IsEither type.
			assert((other == nullptr) != (type == AtMostOnePointer));
		}
	};
	
	class ConstraintContext
	{
		unordered_set<Function*> analyzedFunctions;
		deque<LinkedValues> linkedValues;
		unordered_map<Value*, ValueTypeConstraint> valueTypes;
		
		pair<ValueTypeConstraint*, bool> createConstraint(ValueTypeConstraint::Type type, Value& value, Value* other = nullptr)
		{
			linkedValues.emplace_back();
			auto& linkedSet = linkedValues.back();
			auto insertIter = valueTypes.insert({&value, ValueTypeConstraint(ValueTypeConstraint::Either, &linkedSet, value, other)});
			return {&insertIter.first->second, insertIter.second};
		}
		
		void unifyValueTypes(ValueTypeConstraint& left, ValueTypeConstraint& right)
		{
			LinkedValues* assimilating = nullptr;
			LinkedValues* assimilated = nullptr;
			if (left.sameTypeSet->size() < right.sameTypeSet->size())
			{
				assimilating = right.sameTypeSet;
				assimilated = left.sameTypeSet;
			}
			else
			{
				assimilating = left.sameTypeSet;
				assimilated = right.sameTypeSet;
			}
			
			for (auto info : *assimilated)
			{
				info->sameTypeSet = assimilating;
				assimilating->insert(info);
			}
			assimilated->clear();
		}
		
		bool refineType(ValueTypeConstraint& constraint, ValueTypeConstraint::Type newType)
		{
			assert(newType != ValueTypeConstraint::Unset);
			ValueTypeConstraint::Type oldType = constraint.type;
			switch (constraint.type)
			{
				case ValueTypeConstraint::Unset:
					llvm_unreachable("Creating a constraint of unset type shouldn't be possible!");
					
				case ValueTypeConstraint::Either:
					assert(newType == ValueTypeConstraint::IsPointer || newType == ValueTypeConstraint::IsInteger);
					constraint.type = newType;
					break;
					
				case ValueTypeConstraint::AtMostOnePointer:
				{
					auto& otherConstraint = *getConstraintForValue(*constraint.otherValue);
					assert(otherConstraint.type == ValueTypeConstraint::AtMostOnePointer);
					switch (newType)
					{
						case ValueTypeConstraint::IsPointer:
							// exciting!
							constraint.type = ValueTypeConstraint::IsPointer;
							otherConstraint.type = ValueTypeConstraint::IsInteger;
							constraint.otherValue = nullptr;
							otherConstraint.otherValue = nullptr;
							break;
							
						case ValueTypeConstraint::IsInteger:
							// sadface.
							constraint.type = ValueTypeConstraint::IsInteger;
							otherConstraint.type = ValueTypeConstraint::Either;
							constraint.otherValue = nullptr;
							otherConstraint.otherValue = nullptr;
							break;
							
						case ValueTypeConstraint::Either:
							// already more refined
							break;
							
						default:
							llvm_unreachable("Illegal constraint transition!");
					}
					break;
				}
					
				case ValueTypeConstraint::IsPointer:
					// Ignore any other transition. Conflicts between pointers and integers are resolved as "this is a
					// pointer".
					break;
					
				case ValueTypeConstraint::IsInteger:
					if (newType == ValueTypeConstraint::IsPointer)
					{
						// (see above case)
						constraint.type = newType;
					}
					break;
			}
			return oldType != constraint.type;
		}
		
		ValueTypeConstraint* getConstraintForValue(Value& value)
		{
			if (!value.getType()->isPointerTy() && !value.getType()->isIntegerTy())
			{
				return nullptr;
			}
			
			auto creationResult = createConstraint(ValueTypeConstraint::Either, value);
			if (!creationResult.second)
			{
				return creationResult.first;
			}
			
			auto& valueType = *creationResult.first;
			// Casts merely forward other object addresses.
			if (auto castInst = dyn_cast<CastInst>(&value))
			{
				switch (castInst->getOpcode())
				{
					case Instruction::ZExt:
					case Instruction::IntToPtr:
					case Instruction::BitCast:
					case Instruction::AddrSpaceCast:
						if (auto operandConstraint = getConstraintForValue(*castInst->getOperand(0)))
						{
							unifyValueTypes(valueType, *operandConstraint);
						}
						break;
					default: break;
				}
			}
			
			// Values that are already pointers
			if (value.getType()->isPointerTy())
			{
				valueType.type = ValueTypeConstraint::IsPointer;
			}
			// Values that are the "Y combination" of previous values
			else if (auto select = dyn_cast<SelectInst>(&value))
			{
				if (auto constraint = getConstraintForValue(*select->getTrueValue()))
				{
					unifyValueTypes(valueType, *constraint);
				}
				if (auto constraint = getConstraintForValue(*select->getFalseValue()))
				{
					unifyValueTypes(valueType, *constraint);
				}
			}
			else if (auto phi = dyn_cast<PHINode>(&value))
			{
				for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i)
				{
					unifyValueTypes(valueType, *getConstraintForValue(*phi->getIncomingValue(i)));
				}
			}
			// Instructions that operate on both pointers-as-integers and integers
			else if (auto binaryOp = dyn_cast<BinaryOperator>(&value))
			{
				if (binaryOp->getOpcode() == BinaryOperator::Add || binaryOp->getOpcode() == BinaryOperator::Sub)
				{
					// Since constants are a pain to deal with in this process in general (they are uniqued in the
					// module, but we don't want to infer every use of the same value as the same type), look here if
					// there is a constant
				}
			}
			
			return &valueType;
		}
		
		void analyzeFunction(Function& fn)
		{
			auto insertResult = analyzedFunctions.insert(&fn);
			if (!insertResult.second)
			{
				return;
			}
			
			bool argumentsAreExact = md::areArgumentsExact(fn);
			for (Argument& arg : fn.args())
			{
				ValueTypeConstraint::Type type = ValueTypeConstraint::Unset;
				if (argumentsAreExact)
				{
					if (arg.getType()->isPointerTy())
					{
						type = ValueTypeConstraint::IsPointer;
					}
					else if (arg.getType()->isIntegerTy())
					{
						type = ValueTypeConstraint::IsInteger;
					}
				}
				else if (arg.getType()->isIntegerTy())
				{
					type = ValueTypeConstraint::Either;
				}
				
				if (type != ValueTypeConstraint::Unset)
				{
					auto result = createConstraint(ValueTypeConstraint::Either, arg);
					assert(result.second); (void) result;
				}
			}
			
			if (md::isPrototype(fn))
			{
				return;
			}
			
			for (BasicBlock& bb : fn)
			{
				for (Instruction& inst : bb)
				{
					(void) getConstraintForValue(inst);
				}
			}
		}
		
	public:
		void analyzeModule(Module& module)
		{
			for (Function& fn : module)
			{
				analyzeFunction(fn);
			}
			
			// Resolve constraints
		}
	};
}

void ObjectAddress::dump() const
{
	print(errs());
	errs() << '\n';
}

RootObjectAddress& RootObjectAddress::getRoot()
{
	return *this;
}

int64_t RootObjectAddress::getOffsetFromRoot() const
{
	return 0;
}

void RootObjectAddress::print(raw_ostream& os) const
{
	os << '{';
	value->printAsOperand(os);
	printFunctionSuffix(os, *value);
	os << '}';
}

RelativeObjectAddress::RelativeObjectAddress(Type type, NOT_NULL(Value) value, UnificationSet unification, NOT_NULL(ObjectAddress) parent)
: ObjectAddress(type, value, unification), parent(parent)
{
}

RootObjectAddress& RelativeObjectAddress::getRoot()
{
	return parent->getRoot();
}

int64_t ConstantOffsetObjectAddress::getOffsetFromRoot() const
{
	// Assume index=0: in other words, return same offset as parent.
	return offset;
}

void ConstantOffsetObjectAddress::print(raw_ostream& os) const
{
	parent->print(os);
	os << " + " << offset;
}

int64_t VariableOffsetObjectAddress::getOffsetFromRoot() const
{
	// Assume index=0: in other words, return same offset as parent.
	return parent->getOffsetFromRoot();
}

void VariableOffsetObjectAddress::print(raw_ostream& os) const
{
	parent->print(os);
	os << " + {";
	index->printAsOperand(os);
	printFunctionSuffix(os, *index);
	os << " * " << stride << '}';
}

void PointerDiscovery::analyzeModule(Executable& executable, Module& module)
{
	pool.clear();
	unificationSets.clear();
	addressesInFunctions.clear();
	roots.clear();
	this->executable = &executable;
	
	for (auto& function : module)
	{
		analyzeFunction(function);
	}
}
