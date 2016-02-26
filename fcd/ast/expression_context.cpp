//
// expression_context.cpp
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

#include "expression_context.h"
#include "metadata.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/InstVisitor.h>
SILENCE_LLVM_WARNINGS_END()

using namespace std;
using namespace llvm;

namespace
{
	inline void printTypeAsC(raw_ostream& os, Type* type)
	{
		if (type->isVoidTy())
		{
			os << "void";
			return;
		}
		if (type->isIntegerTy())
		{
			size_t width = type->getIntegerBitWidth();
			if (width == 1)
			{
				os << "bool";
			}
			else
			{
				// HACKHACK: this will not do if we ever want to differentiate signed and unsigned values
				os << "int" << width << "_t";
			}
			return;
		}
		if (type->isPointerTy())
		{
			// HACKHACK: this will not do once LLVM gets rid of pointer types
			printTypeAsC(os, type->getPointerElementType());
			os << '*';
			return;
		}
		if (auto arrayType = dyn_cast<ArrayType>(type))
		{
			printTypeAsC(os, arrayType->getElementType());
			os << '[' << arrayType->getNumElements() << ']';
			return;
		}
		if (auto structType = dyn_cast<StructType>(type))
		{
			os << '{';
			unsigned elems = structType->getNumElements();
			if (elems > 0)
			{
				printTypeAsC(os, structType->getElementType(0));
				for (unsigned i = 1; i < elems; ++i)
				{
					os << ", ";
					printTypeAsC(os, structType->getElementType(i));
				}
			}
			os << '}';
			return;
		}
		if (auto fnType = dyn_cast<FunctionType>(type))
		{
			printTypeAsC(os, fnType->getReturnType());
			os << '(';
			unsigned elems = fnType->getNumParams();
			if (elems > 0)
			{
				printTypeAsC(os, fnType->getParamType(0));
				for (unsigned i = 1; i < elems; ++i)
				{
					os << ", ";
					printTypeAsC(os, fnType->getParamType(i));
				}
			}
			os << ')';
			return;
		}
		llvm_unreachable("implement me");
	}
	
	inline string toString(Type* type)
	{
		string result;
		raw_string_ostream ss(result);
		printTypeAsC(ss, type);
		ss.flush();
		return result;
	}
	
	NAryOperatorExpression::NAryOperatorType getOperator(BinaryOperator::BinaryOps op)
	{
#define MAP_OP(x, y) [BinaryOperator::x] = NAryOperatorExpression::y
		static NAryOperatorExpression::NAryOperatorType operatorMap[] =
		{
			MAP_OP(Add, Add),
			MAP_OP(FAdd, Add),
			MAP_OP(Sub, Subtract),
			MAP_OP(FSub, Subtract),
			MAP_OP(Mul, Multiply),
			MAP_OP(FMul, Multiply),
			MAP_OP(UDiv, Divide),
			MAP_OP(SDiv, Divide),
			MAP_OP(FDiv, Divide),
			MAP_OP(URem, Modulus),
			MAP_OP(SRem, Modulus),
			MAP_OP(FRem, Modulus),
			MAP_OP(Shl, ShiftLeft),
			MAP_OP(LShr, ShiftRight),
			MAP_OP(AShr, ShiftRight),
			MAP_OP(And, BitwiseAnd),
			MAP_OP(Or, BitwiseOr),
			MAP_OP(Xor, BitwiseXor),
		};
#undef MAP_OP
		
		assert(op >= BinaryOperator::BinaryOpsBegin && op < BinaryOperator::BinaryOpsEnd);
		return operatorMap[op];
	}
	
	NAryOperatorExpression::NAryOperatorType getOperator(CmpInst::Predicate pred)
	{
#define MAP_OP(x, y) [CmpInst::x] = NAryOperatorExpression::y
		// "Max" is for invalid operators.
		static NAryOperatorExpression::NAryOperatorType operatorMap[] =
		{
			MAP_OP(FCMP_FALSE, Max),
			MAP_OP(FCMP_OEQ, Equal),
			MAP_OP(FCMP_OGT, GreaterThan),
			MAP_OP(FCMP_OGE, GreaterOrEqualTo),
			MAP_OP(FCMP_OLT, SmallerThan),
			MAP_OP(FCMP_OLE, SmallerOrEqualTo),
			MAP_OP(FCMP_ONE, NotEqual),
			MAP_OP(FCMP_ORD, Max),
			MAP_OP(FCMP_UNO, Max),
			MAP_OP(FCMP_UEQ, Max),
			MAP_OP(FCMP_UGT, Max),
			MAP_OP(FCMP_UGE, Max),
			MAP_OP(FCMP_ULT, Max),
			MAP_OP(FCMP_ULE, Max),
			MAP_OP(FCMP_UNE, Max),
			MAP_OP(FCMP_TRUE, Max),
			
			MAP_OP(ICMP_EQ, Equal),
			MAP_OP(ICMP_NE, NotEqual),
			MAP_OP(ICMP_UGT, GreaterThan),
			MAP_OP(ICMP_UGE, GreaterOrEqualTo),
			MAP_OP(ICMP_ULT, SmallerThan),
			MAP_OP(ICMP_ULE, SmallerOrEqualTo),
			MAP_OP(ICMP_SGT, GreaterThan),
			MAP_OP(ICMP_SGE, GreaterOrEqualTo),
			MAP_OP(ICMP_SLT, SmallerThan),
			MAP_OP(ICMP_SLE, SmallerOrEqualTo),
		};
#undef MAP_OP
		
		assert(pred < CmpInst::BAD_ICMP_PREDICATE || pred < CmpInst::BAD_FCMP_PREDICATE);
		return operatorMap[pred];
	}
}

#define VISIT(T) Expression* visit##T(T& inst)

class InstToExpr : public llvm::InstVisitor<InstToExpr, Expression*>
{
	ExpressionContext& ctx;
	
	DumbAllocator& pool()
	{
		return ctx.pool;
	}
	
	Expression* valueFor(Value& value)
	{
		return ctx.expressionFor(value);
	}
	
	template<typename T, typename... TArgs>
	T* allocate(TArgs&&... args)
	{
		return allocate<T>(std::forward<TArgs>(args)...);
	}
	
	Expression* indexIntoElement(Module& module, Expression* base, Type* type, Value* index)
	{
		if (type->isPointerTy() || type->isArrayTy())
		{
			return allocate<SubscriptExpression>(base, valueFor(*index));
		}
		else if (auto structType = dyn_cast<StructType>(type))
		{
			if (auto constant = dyn_cast<ConstantInt>(index))
			{
				unsigned fieldIndex = static_cast<unsigned>(constant->getLimitedValue());
				
				// TODO: this should probably be organized into some kind of name registry
				string fieldName = md::getRecoveredReturnFieldName(module, *structType, fieldIndex).str();
				if (fieldName == "")
				{
					raw_string_ostream(fieldName) << "field" << fieldIndex;
				}
				
				auto token = allocate<TokenExpression>(pool(), fieldName);
				return allocate<NAryOperatorExpression>(pool(), NAryOperatorExpression::MemberAccess, base, token);
			}
			assert(false && "not implemented");
			return nullptr;
		}
		else
		{
			assert(false && "not implemented");
			return nullptr;
		}
	}
	
public:
	InstToExpr(ExpressionContext& ctx)
	: ctx(ctx)
	{
	}
	
	Expression* visitValue(Value& val)
	{
		if (auto inst = dyn_cast<Instruction>(&val))
		{
			return visit(inst);
		}
		else if (auto constant = dyn_cast<Constant>(&val))
		{
			return visitConstant(*constant);
		}
		else if (auto arg = dyn_cast<Argument>(&val))
		{
			return allocate<TokenExpression>(pool(), arg->getName());
		}
		llvm_unreachable("unexpected type of value");
	}
	
	Expression* visitConstant(Constant& constant)
	{
		if (auto constantInt = dyn_cast<ConstantInt>(&constant))
		{
			return allocate<NumericExpression>(constantInt->getLimitedValue());
		}
		
		if (auto expression = dyn_cast<ConstantExpr>(&constant))
		{
			unique_ptr<Instruction> asInst(expression->getAsInstruction());
			return ctx.uncachedExpressionFor(*asInst);
		}
		
		if (auto structure = dyn_cast<ConstantStruct>(&constant))
		{
			auto agg = allocate<AggregateExpression>(pool());
			unsigned items = structure->getNumOperands();
			for (unsigned i = 0; i < items; ++i)
			{
				auto operand = structure->getOperand(i);
				agg->values.push_back(valueFor(*operand));
			}
			return agg;
		}
		
		if (auto zero = dyn_cast<ConstantAggregateZero>(&constant))
		{
			auto agg = allocate<AggregateExpression>(pool());
			unsigned items = zero->getNumElements();
			for (unsigned i = 0; i < items; ++i)
			{
				auto operand = zero->getStructElement(i);
				agg->values.push_back(valueFor(*operand));
			}
			return agg;
		}
		
		if (auto func = dyn_cast<Function>(&constant))
		{
			if (auto asmString = md::getAssemblyString(*func))
			{
				AssemblyExpression* asmExpr = allocate<AssemblyExpression>(pool(), asmString->getString());
				for (const auto& arg : func->args())
				{
					asmExpr->addParameterName(arg.getName());
				}
				return asmExpr;
			}
			else
			{
				return allocate<TokenExpression>(pool(), func->getName().str());
			}
		}
		
		if (isa<UndefValue>(constant))
		{
			return allocate<TokenExpression>(pool(), "__undefined");
		}
		
		if (isa<ConstantPointerNull>(constant))
		{
			return allocate<TokenExpression>(pool(), "__null");
		}
		
		llvm_unreachable("unexpected type of constant");
	}
	
	Expression* visitInstruction(Instruction& inst)
	{
		llvm_unreachable("unexpected type of instruction");
	}
	
	VISIT(PHINode)
	{
		return allocate<AssignableExpression>(pool(), toString(inst.getType()), "phi");
	}
	
	VISIT(AllocaInst)
	{
		auto variable = allocate<AssignableExpression>(pool(), toString(inst.getType()), "alloca");
		return allocate<UnaryOperatorExpression>(UnaryOperatorExpression::AddressOf, variable);
	}
	
	VISIT(LoadInst)
	{
		auto operand = valueFor(*inst.getPointerOperand());
		return allocate<UnaryOperatorExpression>(UnaryOperatorExpression::Dereference, operand);
	}
	
	VISIT(CallInst)
	{
		auto called = valueFor(*inst.getCalledValue());
		auto callExpr = allocate<CallExpression>(pool(), called);
		for (unsigned i = 0; i < inst.getNumArgOperands(); i++)
		{
			auto operand = inst.getArgOperand(i);
			auto opExpr = valueFor(*operand);
			callExpr->parameters.push_back(opExpr);
		}
		return callExpr;
	}
	
	VISIT(BinaryOperator)
	{
		auto left = valueFor(*inst.getOperand(0));
		auto right = valueFor(*inst.getOperand(1));
		return allocate<NAryOperatorExpression>(pool(), getOperator(inst.getOpcode()), left, right);
	}
	
	VISIT(CmpInst)
	{
		auto left = valueFor(*inst.getOperand(0));
		auto right = valueFor(*inst.getOperand(1));
		return allocate<NAryOperatorExpression>(pool(), getOperator(inst.getPredicate()), left, right);
	}
	
	VISIT(SelectInst)
	{
		auto condition = valueFor(*inst.getCondition());
		auto ifTrue = valueFor(*inst.getTrueValue());
		auto ifFalse = valueFor(*inst.getFalseValue());
		return allocate<TernaryExpression>(condition, ifTrue, ifFalse);
	}
	
	VISIT(InsertValueInst)
	{
		// we will clearly need additional work for InsertValueInsts that go deeper than the first level
		assert(inst.getNumIndices() == 1);
		
		auto baseValue = cast<AggregateExpression>(valueFor(*inst.getAggregateOperand()));
		auto newItem = valueFor(*inst.getInsertedValueOperand());
		return baseValue->copyWithNewItem(pool(), inst.getIndices()[0], newItem);
	}
	
	VISIT(ExtractValueInst)
	{
		Module& module = *inst.getParent()->getParent()->getParent();
		
		auto i64 = Type::getInt64Ty(inst.getContext());
		auto rawIndices = inst.getIndices();
		Type* baseType = inst.getOperand(0)->getType();
		
		Expression* result = valueFor(*inst.getAggregateOperand());
		for (unsigned i = 0; i < rawIndices.size(); ++i)
		{
			Type* indexedType = ExtractValueInst::getIndexedType(baseType, rawIndices.slice(0, i));
			result = indexIntoElement(module, result, indexedType, ConstantInt::get(i64, rawIndices[i]));
		}
		return result;
	}
	
	VISIT(GetElementPtrInst)
	{
		Module& module = *inst.getParent()->getParent()->getParent();
		vector<Value*> indices;
		copy(inst.idx_begin(), inst.idx_end(), back_inserter(indices));
		
		// special case for index 0, since baseType is not a pointer type (but GEP operand 0 operates on a pointer type)
		Expression* result = allocate<SubscriptExpression>(valueFor(*inst.getPointerOperand()), valueFor(*indices[0]));
		
		Type* baseType = inst.getSourceElementType();
		ArrayRef<Value*> rawIndices = indices;
		for (unsigned i = 1; i < indices.size(); ++i)
		{
			Type* indexedType = GetElementPtrInst::getIndexedType(baseType, rawIndices.slice(0, i));
			result = indexIntoElement(module, result, indexedType, indices[i]);
		}
		return allocate<UnaryOperatorExpression>(UnaryOperatorExpression::AddressOf, result);
	}
	
	VISIT(CastInst)
	{
		auto type = allocate<TokenExpression>(pool(), toString(inst.getDestTy()));
		CastExpression::CastSign sign =
			inst.getOpcode() == Instruction::SExt ? CastExpression::SignExtend :
			inst.getOpcode() == Instruction::ZExt ? CastExpression::ZeroExtend :
			CastExpression::Irrelevant;
		return allocate<CastExpression>(type, valueFor(*inst.getOperand(0)), sign);
	}
};

ExpressionContext::ExpressionContext(DumbAllocator& pool)
: pool(pool)
{
}

Expression* ExpressionContext::uncachedExpressionFor(llvm::Value& value)
{
	auto iter = expressionMap.find(&value);
	if (iter != expressionMap.end())
	{
		return iter->second;
	}
	
	InstToExpr visitor(*this);
	return visitor.visitValue(value);
}

Expression* ExpressionContext::expressionFor(Value& value)
{
	auto& expr = expressionMap[&value];
	if (expr == nullptr)
	{
		InstToExpr visitor(*this);
		expr = visitor.visitValue(value);
	}
	return expr;
}
