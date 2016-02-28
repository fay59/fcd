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

#include "ast_context.h"
#include "expressions.h"
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
	AstContext& ctx;
	
	DumbAllocator& pool()
	{
		return ctx.pool;
	}
	
	Expression* valueFor(Value& value)
	{
		return ctx.expressionFor(value);
	}
	
	Expression* indexIntoElement(Module& module, Expression* base, Type* type, Value* index)
	{
		if (type->isPointerTy() || type->isArrayTy())
		{
			return ctx.subscript(base, valueFor(*index));
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
				
				auto token = ctx.token(fieldName);
				return ctx.nary(NAryOperatorExpression::MemberAccess, base, token);
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
	InstToExpr(AstContext& ctx)
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
			return ctx.token(arg->getName());
		}
		llvm_unreachable("unexpected type of value");
	}
	
	Expression* visitConstant(Constant& constant)
	{
		if (auto constantInt = dyn_cast<ConstantInt>(&constant))
		{
			return ctx.numeric(constantInt->getLimitedValue());
		}
		
		if (auto expression = dyn_cast<ConstantExpr>(&constant))
		{
			unique_ptr<Instruction> asInst(expression->getAsInstruction());
			return ctx.uncachedExpressionFor(*asInst);
		}
		
		if (auto structure = dyn_cast<ConstantStruct>(&constant))
		{
			unsigned items = structure->getNumOperands();
			auto agg = ctx.aggregate(items);
			for (unsigned i = 0; i < items; ++i)
			{
				auto operand = structure->getOperand(i);
				agg->setOperand(i, valueFor(*operand));
			}
			return agg;
		}
		
		if (auto zero = dyn_cast<ConstantAggregateZero>(&constant))
		{
			unsigned items = zero->getNumElements();
			auto agg = ctx.aggregate(items);
			for (unsigned i = 0; i < items; ++i)
			{
				auto operand = zero->getStructElement(i);
				agg->setOperand(i, valueFor(*operand));
			}
			return agg;
		}
		
		if (auto func = dyn_cast<Function>(&constant))
		{
			if (auto asmString = md::getAssemblyString(*func))
			{
				AssemblyExpression* asmExpr = ctx.assembly(asmString->getString());
				for (const auto& arg : func->args())
				{
					asmExpr->addParameterName(arg.getName());
				}
				return asmExpr;
			}
			else
			{
				return ctx.token(func->getName());
			}
		}
		
		if (isa<UndefValue>(constant))
		{
			return ctx.expressionForUndef();
		}
		
		if (isa<ConstantPointerNull>(constant))
		{
			return ctx.expressionForNull();
		}
		
		llvm_unreachable("unexpected type of constant");
	}
	
	Expression* visitInstruction(Instruction& inst)
	{
		llvm_unreachable("unexpected type of instruction");
	}
	
	VISIT(PHINode)
	{
		return ctx.assignable(ctx.expressionFor(*inst.getType()), "phi");
	}
	
	VISIT(AllocaInst)
	{
		auto variable = ctx.assignable(ctx.expressionFor(*inst.getType()), "alloca");
		return ctx.unary(UnaryOperatorExpression::AddressOf, variable);
	}
	
	VISIT(LoadInst)
	{
		auto operand = valueFor(*inst.getPointerOperand());
		return ctx.unary(UnaryOperatorExpression::Dereference, operand);
	}
	
	VISIT(CallInst)
	{
		unsigned numParameters = inst.getNumArgOperands();
		auto called = valueFor(*inst.getCalledValue());
		auto callExpr = ctx.call(called, numParameters);
		for (unsigned i = 0; i < inst.getNumArgOperands(); i++)
		{
			auto operand = inst.getArgOperand(i);
			callExpr->setParameter(i, valueFor(*operand));
		}
		return callExpr;
	}
	
	VISIT(BinaryOperator)
	{
		auto left = valueFor(*inst.getOperand(0));
		auto right = valueFor(*inst.getOperand(1));
		return ctx.nary(getOperator(inst.getOpcode()), left, right);
	}
	
	VISIT(CmpInst)
	{
		auto left = valueFor(*inst.getOperand(0));
		auto right = valueFor(*inst.getOperand(1));
		return ctx.nary(getOperator(inst.getPredicate()), left, right);
	}
	
	VISIT(SelectInst)
	{
		auto condition = valueFor(*inst.getCondition());
		auto ifTrue = valueFor(*inst.getTrueValue());
		auto ifFalse = valueFor(*inst.getFalseValue());
		return ctx.ternary(condition, ifTrue, ifFalse);
	}
	
	VISIT(InsertValueInst)
	{
		// we will clearly need additional work for InsertValueInsts that go deeper than the first level
		assert(inst.getNumIndices() == 1);
		
		auto baseValue = cast<AggregateExpression>(valueFor(*inst.getAggregateOperand()));
		auto newItem = valueFor(*inst.getInsertedValueOperand());
		return baseValue->copyWithNewItem(inst.getIndices()[0], newItem);
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
		Expression* result = ctx.subscript(valueFor(*inst.getPointerOperand()), valueFor(*indices[0]));
		
		Type* baseType = inst.getSourceElementType();
		ArrayRef<Value*> rawIndices = indices;
		for (unsigned i = 1; i < indices.size(); ++i)
		{
			Type* indexedType = GetElementPtrInst::getIndexedType(baseType, rawIndices.slice(0, i));
			result = indexIntoElement(module, result, indexedType, indices[i]);
		}
		return ctx.unary(UnaryOperatorExpression::AddressOf, result);
	}
	
	VISIT(CastInst)
	{
		auto type = ctx.expressionFor(*inst.getDestTy());
		CastExpression::CastSign sign =
			inst.getOpcode() == Instruction::SExt ? CastExpression::SignExtend :
			inst.getOpcode() == Instruction::ZExt ? CastExpression::ZeroExtend :
			CastExpression::Irrelevant;
		return ctx.cast(type, valueFor(*inst.getOperand(0)), sign);
	}
};

void* AstContext::prepareStorageAndUses(unsigned useCount, size_t storage)
{
	size_t useDataSize = useCount == 0 ? 0 : sizeof(ExpressionUseArrayHead) + sizeof(ExpressionUse) * useCount;
	size_t totalSize = useDataSize + storage;
	auto pointer = pool.allocateDynamic<char>(totalSize, alignof(void*));
	
	// Prepare use data
	if (useDataSize > 0)
	{
		auto nextUseArray = reinterpret_cast<ExpressionUseArrayHead*>(pointer);
		new (nextUseArray) ExpressionUseArrayHead;
		
		auto useBegin = reinterpret_cast<ExpressionUse*>(&nextUseArray[1]);
		auto useEnd = useBegin + useCount;
		auto firstUse = useEnd - 1;
		
		ptrdiff_t bitsToEncode = 0;
		auto useIter = useEnd;
		while (useIter != useBegin)
		{
			--useIter;
			ExpressionUse::PrevTag tag;
			if (bitsToEncode == 0)
			{
				tag = useIter == firstUse ? ExpressionUse::FullStop : ExpressionUse::Stop;
				bitsToEncode = useEnd - useIter;
			}
			else
			{
				tag = static_cast<ExpressionUse::PrevTag>(bitsToEncode & 1);
				bitsToEncode >>= 1;
			}
			new (useIter) ExpressionUse(tag);
		}
	}
	
	// The rest of the buffer will be initialized by a placement new
	auto objectStorage = reinterpret_cast<void*>(pointer + useDataSize);
	assert((reinterpret_cast<uintptr_t>(objectStorage) & (alignof(void*) - 1)) == 0);
	return objectStorage;
}

AstContext::AstContext(DumbAllocator& pool)
: pool(pool)
{
	trueExpr = token("true");
	undef = token("__undefined");
	null = token("null");
}

Expression* AstContext::uncachedExpressionFor(llvm::Value& value)
{
	auto iter = expressionMap.find(&value);
	if (iter != expressionMap.end())
	{
		return iter->second;
	}
	
	InstToExpr visitor(*this);
	return visitor.visitValue(value);
}

TokenExpression* AstContext::expressionFor(Type& type)
{
	auto& typeToken = typeMap[&type];
	if (typeToken == nullptr)
	{
		typeToken = token(toString(&type));
	}
	return typeToken;
}

Expression* AstContext::expressionFor(Value& value)
{
	auto& expr = expressionMap[&value];
	if (expr == nullptr)
	{
		InstToExpr visitor(*this);
		expr = visitor.visitValue(value);
	}
	return expr;
}

Statement* AstContext::statementFor(Instruction &inst)
{
	// Most instructions do not create a statement. Only terminators and memory instructions (calls included) do.
	if (auto store = dyn_cast<StoreInst>(&inst))
	{
		Expression* location = expressionFor(*store->getPointerOperand());
		Expression* deref = unary(UnaryOperatorExpression::Dereference, location);
		Expression* value = expressionFor(*store->getValueOperand());
		Expression* assignment = nary(NAryOperatorExpression::Assign, deref, value);
		return expr(assignment);
	}
	
	if (auto call = dyn_cast<CallInst>(&inst))
	{
		Expression* callExpr = expressionFor(*call);
		return expr(callExpr);
	}
	
	if (auto terminator = dyn_cast<TerminatorInst>(&inst))
	{
		if (auto ret = dyn_cast<ReturnInst>(terminator))
		{
			Expression* returnValue = nullptr;
			if (auto retVal = ret->getReturnValue())
			{
				returnValue = expressionFor(*retVal);
			}
			return keyword("return", returnValue);
		}
		return nullptr;
	}
	
	// otherwise, create the value but don't return any statement.
	(void)expressionFor(inst);
	return nullptr;
}

Expression* AstContext::negate(NOT_NULL(Expression) expr)
{
	if (auto unary = dyn_cast<UnaryOperatorExpression>(expr))
	if (unary->type == UnaryOperatorExpression::LogicalNegate)
	{
		return unary->getOperand();
	}
	return unary(UnaryOperatorExpression::LogicalNegate, expr);
}
