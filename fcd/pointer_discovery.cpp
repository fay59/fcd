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
	
	struct TypeConstraint
	{
		enum Type
		{
			// We know that this is a pointer
			Pointer,
			// We know that this is an integer
			Integer,
			// This is a pointer if that other value is also a pointer.
			PointerIf,
			// At most one of `thisValue` and `otherValue` is a pointer
			MaxOnePointer,
			// Both `thisValue` and `otherValue` (probably) have the same type. This constraint is the prime candidate
			// to be broken if a contradiction arises.
			AreSameType,
		};
		
		Value& thisValue;
		Value* otherValue;
		Type type;
		
		TypeConstraint(Type type, Value& thisValue, Value* other = nullptr)
		: type(type), thisValue(thisValue), otherValue(other)
		{
			// Make sure that we have an other value only when the constraint type allows for it.
			assert((other == nullptr) == (type == Pointer || type == Integer));
		}
	};
	
	struct ConstraintInfo
	{
		enum InferredType
		{
			Either,
			Pointer,
			Integer,
			Both,
		};
		
		Value& value;
		deque<TypeConstraint*> constraints; // Pointer, Integer first; MaxOnePointer, AreSameType last
		InferredType type;
		
		ConstraintInfo(Value& value)
		: value(value), type(Either)
		{
		}
	};
	
	class ConstraintContext
	{
		Executable& executable;
		unordered_set<Function*> analyzedFunctions;
		deque<TypeConstraint> constraints;
		unordered_map<Value*, ConstraintInfo> groupedConstraints;
		deque<unordered_set<Value*>> sameTypeSets;
		unordered_map<Value*, unordered_set<Value*>*> sameTypeMap;
		
		Value& constrainPossibleGlobalAddress(Use& use)
		{
			// Constant integers are uniqued in the module, which means that repetitions of the constant will all
			// appear to be tied together. We don't want that. One solution is to wrap every constant in an instruction.
			// It's ugly, but it makes everything simpler and it goes away easily later.
			Value* value = use.get();
			if (auto constantInt = dyn_cast<ConstantInt>(value))
			{
				value = CastInst::Create(CastInst::ZExt, constantInt, constantInt->getType(), "", cast<Instruction>(use.getUser()));
				use.set(value);
				
				// If this constant matches an address, tentatively create a constraint for it to avoid silly results.
				// Otherwise, expressions like {i64 0x602224 + i64 %i} end up making %i the variable and 0x602224 the
				// field offset.
				// XXX: executables that map page 0 will probably make this painful.
				if (executable.map(constantInt->getLimitedValue()) != nullptr)
				{
					constrain(TypeConstraint::Pointer, *value);
				}
			}
			return *value;
		}
		
		Value& constrainPossibleGlobalAddress(Value& value)
		{
			return value;
		}
		
		template<typename Arg1>
		void constrain(TypeConstraint::Type type, Arg1& value)
		{
			Value& first = constrainPossibleGlobalAddress(value);
			constraints.emplace_back(type, first);
		}
		
		template<typename Arg1, typename Arg2>
		void constrain(TypeConstraint::Type type, Arg1& value, Arg2& other)
		{
			Value& first = constrainPossibleGlobalAddress(value);
			Value& second = constrainPossibleGlobalAddress(other);
			constraints.emplace_back(type, first, &second);
		}
		
		void constrainValue(Value& value)
		{
			// Only constrain integer-like values.
			if (!value.getType()->isPointerTy() && !value.getType()->isIntegerTy())
			{
				return;
			}
			
			// Casts merely forward other object addresses.
			if (auto castInst = dyn_cast<CastInst>(&value))
			{
				switch (castInst->getOpcode())
				{
					case Instruction::ZExt:
					case Instruction::IntToPtr:
					case Instruction::BitCast:
					case Instruction::AddrSpaceCast:
						// Assume that the cast exists for lack of type information, not because a cast is actually
						// needed, and attempt to constrain the two to be the same thing.
						constrain(TypeConstraint::AreSameType, *castInst, castInst->getOperandUse(0));
						break;
					default: break;
				}
			}
			
			// Values that are already pointers
			if (value.getType()->isPointerTy())
			{
				constrain(TypeConstraint::Pointer, value);
			}
			// Values that are the "Y combination" of previous values
			else if (auto select = dyn_cast<SelectInst>(&value))
			{
				constrain(TypeConstraint::AreSameType, value, select->getOperandUse(1));
				constrain(TypeConstraint::AreSameType, value, select->getOperandUse(2));
			}
			else if (auto phi = dyn_cast<PHINode>(&value))
			{
				for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i)
				{
					constrain(TypeConstraint::AreSameType, value, phi->getOperandUse(1));
				}
			}
			// Instructions that operate on both pointers-as-integers and integers
			else if (auto binaryOp = dyn_cast<BinaryOperator>(&value))
			{
				if (binaryOp->getOpcode() == BinaryOperator::Add || binaryOp->getOpcode() == BinaryOperator::Sub)
				{
					constrain(TypeConstraint::MaxOnePointer, binaryOp->getOperandUse(0), binaryOp->getOperandUse(1));
					constrain(TypeConstraint::PointerIf, *binaryOp, binaryOp->getOperandUse(0));
					constrain(TypeConstraint::PointerIf, *binaryOp, binaryOp->getOperandUse(1));
				}
				else
				{
					// Can't be a pointer.
					constrain(TypeConstraint::Integer, value);
					constrain(TypeConstraint::AreSameType, value, binaryOp->getOperandUse(0));
					constrain(TypeConstraint::AreSameType, value, binaryOp->getOperandUse(1));
				}
			}
			// Calls
			else if (auto call = dyn_cast<CallInst>(&value))
			{
				if (auto callee = call->getCalledFunction())
				{
					unsigned argIndex = 0;
					for (Argument& arg : callee->args())
					{
						constrain(TypeConstraint::AreSameType, arg, call->getArgOperandUse(argIndex));
					}
				}
			}
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
				if (argumentsAreExact)
				{
					if (arg.getType()->isPointerTy())
					{
						constrain(TypeConstraint::Pointer, arg);
					}
					else if (arg.getType()->isIntegerTy())
					{
						constrain(TypeConstraint::Integer, arg);
					}
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
					constrainValue(inst);
				}
			}
		}
		
		size_t connectivity(TypeConstraint& constraint) const
		{
			auto& leftGroup = groupedConstraints.at(&constraint.thisValue);
			auto& rightGroup = groupedConstraints.at(constraint.otherValue);
			return min(leftGroup.constraints.size(), rightGroup.constraints.size());
		}
		
		bool connectivityLess(TypeConstraint* a, TypeConstraint* b) const
		{
			return connectivity(*b) < connectivity(*a);
		}
		
		size_t evaluateConstraints(deque<TypeConstraint*>& evaluationList, size_t minimumConnectivity = 0)
		{
			size_t resolved = 0;
			auto compareConnectivity = [=](TypeConstraint* a, TypeConstraint* b) { return connectivityLess(a, b); };
			sort(evaluationList.begin(), evaluationList.end(), compareConnectivity);
			
			auto iter = evaluationList.begin();
			while (iter != evaluationList.end())
			{
				TypeConstraint* constraint = *iter;
				size_t thisConnectivity = connectivity(*constraint);
				if (minimumConnectivity > thisConnectivity)
				{
					break;
				}
				
				bool evaluatedConstraint = false;
				Value& left = constraint->thisValue;
				Value& right = *constraint->otherValue;
				auto& leftGroup = groupedConstraints.insert({&left, {left}}).first->second;
				auto& rightGroup = groupedConstraints.insert({&right, {right}}).first->second;
				Value* discoveredType = nullptr;
				if (constraint->type == TypeConstraint::PointerIf)
				{
					if (leftGroup.type == ConstraintInfo::Pointer)
					{
						evaluatedConstraint = true;
					}
					else if (rightGroup.type == ConstraintInfo::Pointer || rightGroup.type == ConstraintInfo::Both)
					{
						evaluatedConstraint = true;
						
						if (leftGroup.type == ConstraintInfo::Either)
						{
							leftGroup.type = ConstraintInfo::Pointer;
							discoveredType = &left;
							++resolved;
						}
						else if (leftGroup.type == ConstraintInfo::Integer)
						{
							leftGroup.type = ConstraintInfo::Both;
							++resolved;
						}
					}
				}
				else if (constraint->type == TypeConstraint::MaxOnePointer)
				{
					if (leftGroup.type != ConstraintInfo::Either || rightGroup.type != ConstraintInfo::Either)
					{
						if (leftGroup.type == ConstraintInfo::Pointer || leftGroup.type == ConstraintInfo::Both)
						{
							if (rightGroup.type == ConstraintInfo::Either)
							{
								discoveredType = &right;
								rightGroup.type = ConstraintInfo::Integer;
								++resolved;
							}
						}
						else if (rightGroup.type == ConstraintInfo::Pointer || rightGroup.type == ConstraintInfo::Both)
						{
							if (leftGroup.type == ConstraintInfo::Either)
							{
								discoveredType = &left;
								leftGroup.type = ConstraintInfo::Integer;
								++resolved;
							}
						}
						evaluatedConstraint = true;
					}
				}
				else if (constraint->type == TypeConstraint::AreSameType)
				{
					if (leftGroup.type == ConstraintInfo::Both || leftGroup.type == ConstraintInfo::Both)
					{
						evaluatedConstraint = true;
					}
					else
					{
						bool respectedConstraint = false;
						if (leftGroup.type != ConstraintInfo::Either)
						{
							if (rightGroup.type == ConstraintInfo::Either)
							{
								discoveredType = &right;
								rightGroup.type = leftGroup.type;
								evaluatedConstraint = true;
								respectedConstraint = true;
								++resolved;
							}
							else if (rightGroup.type != leftGroup.type)
							{
								leftGroup.type = ConstraintInfo::Both;
								rightGroup.type = ConstraintInfo::Both;
								evaluatedConstraint = true;
								++resolved;
							}
						}
						else if (rightGroup.type != ConstraintInfo::Either)
						{
							if (leftGroup.type == ConstraintInfo::Either)
							{
								discoveredType = &left;
								leftGroup.type = rightGroup.type;
								evaluatedConstraint = true;
								respectedConstraint = true;
								++resolved;
							}
						}
						
						if (respectedConstraint && leftGroup.type == ConstraintInfo::Pointer)
						{
							// Opportunistically build set of pointers that should be of a related type.
							auto*& leftSet = sameTypeMap[&leftGroup.value];
							auto*& rightSet = sameTypeMap[&rightGroup.value];
							if (leftSet == nullptr && rightSet == nullptr)
							{
								sameTypeSets.emplace_back();
								leftSet = &sameTypeSets.back();
								rightSet = &sameTypeSets.back();
								leftSet->insert(&leftGroup.value);
								rightSet->insert(&rightGroup.value); // (of course, both statements insert in the same set.)
							}
							else if (leftSet != nullptr && rightSet != nullptr)
							{
								unordered_set<Value*>* assimilated = nullptr;
								unordered_set<Value*>* assimilating = nullptr;
								if (leftSet->size() < rightSet->size())
								{
									assimilated = leftSet;
									assimilating = rightSet;
								}
								else
								{
									assimilated = rightSet;
									assimilating = leftSet;
								}
								for (auto value : *assimilated)
								{
									assimilating->insert(value);
									sameTypeMap[value] = assimilating;
								}
								assimilated->clear();
								leftSet = assimilating;
								rightSet = assimilating;
							}
							else if (leftSet == nullptr)
							{
								leftSet = rightSet;
								rightSet->insert(&leftGroup.value);
							}
							else
							{
								rightSet = leftSet;
								leftSet->insert(&rightGroup.value);
							}
						}
					}
				}
				else
				{
					llvm_unreachable("How did we get this constraint here?");
				}
				
				if (evaluatedConstraint)
				{
					iter = evaluationList.erase(iter);
				}
				else
				{
					++iter;
				}
				
				if (discoveredType != nullptr)
				{
					deque<TypeConstraint*> subEvaluationList = groupedConstraints.at(discoveredType).constraints;
					resolved += evaluateConstraints(subEvaluationList, thisConnectivity);
					
					// Merge lists. Iterators will be invalidated, but we know that every constraint will go after the
					// current one.
					size_t index = iter - evaluationList.begin();
					for (TypeConstraint* remainingConstraint : subEvaluationList)
					{
						auto insertIter = upper_bound(iter, evaluationList.end(), remainingConstraint, compareConnectivity);
						evaluationList.insert(insertIter, remainingConstraint);
						iter = evaluationList.begin() + index;
					}
				}
			}
			
			return resolved;
		}
		
	public:
		ConstraintContext(Executable& executable)
		: executable(executable)
		{
		}
		
		void analyzeModule(Module& module)
		{
			groupedConstraints.clear();
			sameTypeSets.clear();
			sameTypeMap.clear();
			
			for (Function& fn : module)
			{
				analyzeFunction(fn);
			}
			
			// Resolve constraints. First, group them by target value(s). Grab values that have a known type.
			unordered_set<Value*> valuesWithKnownType;
			for (auto& constraint : constraints)
			{
				auto insertResult = groupedConstraints.insert({&constraint.thisValue, {constraint.thisValue}});
				auto& valueInfo = insertResult.first->second;
				// We can resolve Pointer and Integer constraints right away.
				if (constraint.type == TypeConstraint::Pointer)
				{
					valueInfo.type = ConstraintInfo::Pointer;
					valuesWithKnownType.insert(&valueInfo.value);
				}
				else if (constraint.type == TypeConstraint::Integer)
				{
					valueInfo.type = ConstraintInfo::Integer;
					valuesWithKnownType.insert(&valueInfo.value);
				}
				else
				{
					auto insertResult = groupedConstraints.insert({constraint.otherValue, {*constraint.otherValue}});
					auto& otherValueInfo = insertResult.first->second;
					if (constraint.type == TypeConstraint::MaxOnePointer)
					{
						valueInfo.constraints.push_back(&constraint);
						otherValueInfo.constraints.push_back(&constraint);
					}
					else if (constraint.type == TypeConstraint::PointerIf)
					{
						otherValueInfo.constraints.push_back(&constraint);
					}
					else if (constraint.type == TypeConstraint::AreSameType)
					{
						valueInfo.constraints.push_back(&constraint);
						otherValueInfo.constraints.push_back(&constraint);
					}
					else
					{
						llvm_unreachable("Unknown constraint type!");
					}
				}
			}
			
			// Evaluate constraints in descending order of constraint connectivity. (Do values that reach a large number
			// of nodes first.) This ensures that if we have to break a constraint, the number of casts necessary to
			// make the thing consistent will be minimized.
			deque<TypeConstraint*> evaluationList;
			for (Value* value : valuesWithKnownType)
			{
				auto& group = groupedConstraints.at(value);
				evaluationList.insert(evaluationList.end(), group.constraints.begin(), group.constraints.end());
			}
			
			size_t resolvedConstraints;
			do
			{
				resolvedConstraints = evaluateConstraints(evaluationList);
			}
			while (resolvedConstraints > 0);
			
			// Clean up a bit before returning.
			analyzedFunctions.clear();
			constraints.clear();
			for (auto& pair : groupedConstraints)
			{
				pair.second.constraints.clear();
			}
		}
		
		unordered_map<Function*, unordered_set<Value*>> getPointers() const
		{
			unordered_map<Function*, unordered_set<Value*>> result;
			for (const auto& pair : groupedConstraints)
			{
				const ConstraintInfo& info = pair.second;
				if (info.type == ConstraintInfo::Pointer || info.type == ConstraintInfo::Both)
				{
					if (auto arg = dyn_cast<Argument>(&info.value))
					{
						result[arg->getParent()].insert(arg);
					}
					else if (auto inst = dyn_cast<Instruction>(&info.value))
					{
						result[inst->getParent()->getParent()].insert(inst);
					}
				}
			}
			return result;
		}
		
		const void* getValueTypeSet(Value& value) const
		{
			auto iter = sameTypeMap.find(&value);
			if (iter == sameTypeMap.end())
			{
				return nullptr;
			}
			return &iter->second;
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

template<typename AddressType, typename... Arguments>
AddressType& PointerDiscovery::createAddress(llvm::Value& value, Arguments&&... args)
{
	auto& sameTypeSet = sameTypeSets[context->getValueTypeSet(value)];
	auto address = pool.allocate<AddressType>(&value, &sameTypeSet, forward<Arguments>(args)...);
	sameTypeSet.insert(address);
	addressesByFunction[currentFunction].push_back(address);
	return *address;
}
	
ObjectAddress& PointerDiscovery::handleAddition(ObjectAddress& base, BinaryOperator& totalValue, Value& added, bool positive)
{
	if (auto constant = dyn_cast<ConstantInt>(&added))
	{
		int64_t offset = constant->getLimitedValue() * (positive ? 1 : -1);
		return createAddress<ConstantOffsetObjectAddress>(totalValue, &base, offset);
	}
	
	uint64_t scaleValue = 1;
	Value* index = &added;
	if (auto mul = dyn_cast<BinaryOperator>(&added))
	{
		if (mul->getOpcode() == BinaryOperator::Mul)
		{
			if (auto scale = dyn_cast<ConstantInt>(mul->getOperand(0)))
			{
				scaleValue = scale->getLimitedValue();
				index = mul->getOperand(1);
			}
			else if (auto scale = dyn_cast<ConstantInt>(mul->getOperand(1)))
			{
				scaleValue = scale->getLimitedValue();
				index = mul->getOperand(0);
			}
		}
		else if (mul->getOpcode() == BinaryOperator::Shl)
		{
			if (auto power = dyn_cast<ConstantInt>(mul->getOperand(1)))
			{
				scaleValue = 1ll << power->getLimitedValue();
				index = mul->getOperand(0);
			}
		}
	}
	return createAddress<VariableOffsetObjectAddress>(totalValue, &base, index, scaleValue);
}
	
ObjectAddress& PointerDiscovery::createAddressHierarchy(Value& value)
{
	auto iter = objectAddresses.find(&value);
	if (iter != objectAddresses.end())
	{
		return *iter->second;
	}
	
	if (auto castInst = dyn_cast<CastInst>(&value))
	{
		createAddressHierarchy(*castInst->getOperand(0));
	}
	else if (auto binOp = dyn_cast<BinaryOperator>(&value))
	{
		if (binOp->getOpcode() == BinaryOperator::Add || binOp->getOpcode() == BinaryOperator::Sub)
		{
			Value& left = *binOp->getOperand(0);
			Value& right = *binOp->getOperand(1);
			if (pointerValues->count(&left) != pointerValues->count(&right))
			{
				bool positive = binOp->getOpcode() == BinaryOperator::Add;
				if (pointerValues->count(&left) != 0)
				{
					return handleAddition(createAddressHierarchy(left), *binOp, right, positive);
				}
				else if (pointerValues->count(&right) != 0)
				{
					return handleAddition(createAddressHierarchy(right), *binOp, left, positive);
				}
			}
		}
	}
	
	return createAddress<RootObjectAddress>(value);
}

PointerDiscovery::PointerDiscovery()
{
}

PointerDiscovery::~PointerDiscovery()
{
}

void PointerDiscovery::analyzeModule(Executable& executable, Module& module)
{
	pool.clear();
	
	pointerValues = nullptr;
	currentFunction = nullptr;
	
	sameTypeSets.clear();
	objectAddresses.clear();
	addressesByFunction.clear();
	
	context.reset(new ConstraintContext(executable));
	context->analyzeModule(module);
	
	for (const auto& pair : context->getPointers())
	{
		currentFunction = pair.first;
		pointerValues = &pair.second;
		for (Value* value : *pointerValues)
		{
			createAddressHierarchy(*value);
		}
	}
}
