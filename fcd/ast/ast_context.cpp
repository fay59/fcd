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

#include <llvm/IR/InstVisitor.h>

#include <deque>

using namespace std;
using namespace llvm;

namespace
{
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
		else if (type->isStructTy())
		{
			if (auto constant = dyn_cast<ConstantInt>(index))
			{
				return ctx.memberAccess(base, static_cast<unsigned>(constant->getLimitedValue()));
			}
			llvm_unreachable("not implemented");
		}
		else
		{
			llvm_unreachable("not implemented");
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
			return ctx.token(ctx.getType(*arg->getType()), arg->getName());
		}
		llvm_unreachable("unexpected type of value");
	}
	
	Expression* visitConstant(Constant& constant)
	{
		if (auto constantInt = dyn_cast<ConstantInt>(&constant))
		{
			assert(constantInt->getValue().ule(numeric_limits<uint64_t>::max()));
			return ctx.numeric(ctx.getIntegerType(false, (unsigned short)constantInt->getBitWidth()), constantInt->getLimitedValue());
		}
		
		if (auto expression = dyn_cast<ConstantExpr>(&constant))
		{
			unique_ptr<Instruction> asInst(expression->getAsInstruction());
			return ctx.uncachedExpressionFor(*asInst);
		}
		
		if (auto structure = dyn_cast<ConstantStruct>(&constant))
		{
			unsigned items = structure->getNumOperands();
			auto agg = ctx.aggregate(ctx.getType(*structure->getType()), items);
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
			auto agg = ctx.aggregate(ctx.getType(*zero->getType()), items);
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
				auto& funcType = ctx.createFunction(ctx.getType(*func->getReturnType()));
				for (Argument& arg : func->args())
				{
					funcType.append(ctx.getType(*arg.getType()), arg.getName());
				}
				
				return ctx.assembly(funcType, asmString->getString());
			}
			else
			{
				auto& functionType = ctx.getType(*func->getFunctionType());
				return ctx.token(ctx.getPointerTo(functionType), func->getName());
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
		return ctx.assignable(ctx.getType(*inst.getType()), "phi");
	}
	
	VISIT(AllocaInst)
	{
		auto variable = ctx.assignable(ctx.getType(*inst.getAllocatedType()), "alloca");
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
		
		// special case for a + -const
		if (inst.getOpcode() == BinaryOperator::Add)
		if (auto constant = dyn_cast<NumericExpression>(right))
		{
			const auto& type = constant->getExpressionType(ctx);
			unsigned idleBits = 64 - type.getBits();
			int64_t signedValue = (constant->si64 << idleBits) >> idleBits;
			if (signedValue < 0)
			{
				// I'm pretty sure that we don't need to check for the minimum value for that type
				// since a + INT_MIN is the same as a - INT_MIN.
				auto positiveRight = ctx.numeric(type, static_cast<uint64_t>(-signedValue));
				return ctx.nary(getOperator(BinaryOperator::Sub), left, positiveRight);
			}
		}
		
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
		const ExpressionType* resultType;
		if (inst.getOpcode() == Instruction::SExt)
		{
			resultType = &ctx.getIntegerType(true, (unsigned short)inst.getType()->getIntegerBitWidth());
		}
		else if (inst.getOpcode() == Instruction::ZExt)
		{
			resultType = &ctx.getIntegerType(false, (unsigned short)inst.getType()->getIntegerBitWidth());
		}
		else
		{
			resultType = &ctx.getType(*inst.getDestTy());
		}
		return ctx.cast(*resultType, valueFor(*inst.getOperand(0)));
	}
};

template<>
struct std::hash<pair<const ExpressionType*, size_t>>
{
	std::hash<const ExpressionType*> a;
	std::hash<size_t> b;
	
	size_t operator()(const pair<const ExpressionType*, size_t>& pair) const
	{
		return a(pair.first) ^ b(pair.second);
	}
};

class AstContext::TypeIndex
{
	VoidExpressionType voidType;
	unordered_map<unsigned short, unique_ptr<IntegerExpressionType>> intTypes;
	unordered_map<const ExpressionType*, unique_ptr<PointerExpressionType>> pointerTypes;
	unordered_map<pair<const ExpressionType*, size_t>, unique_ptr<ArrayExpressionType>> arrayTypes;

	// Function types and struct types are managed but not indexed.
	deque<unique_ptr<ExpressionType>> unindexedTypes;
	
public:
	VoidExpressionType& getVoid() { return voidType; }
	
	IntegerExpressionType& getIntegerType(bool isSigned, unsigned short numBits)
	{
		unsigned short key = static_cast<unsigned short>(((isSigned != false) << 15) | (numBits & 0x7fff));
		auto& ptr = intTypes[key];
		if (ptr == nullptr)
		{
			ptr.reset(new IntegerExpressionType(isSigned, numBits));
		}
		return *ptr;
	}
	
	PointerExpressionType& getPointerTo(const ExpressionType& pointee)
	{
		auto& ptr = pointerTypes[&pointee];
		if (ptr == nullptr)
		{
			ptr.reset(new PointerExpressionType(pointee));
		}
		return *ptr;
	}
	
	ArrayExpressionType& getArrayOf(const ExpressionType& elementType, size_t numElements)
	{
		pair<const ExpressionType*, size_t> key(&elementType, numElements);
		auto& ptr = arrayTypes[key];
		if (ptr == nullptr)
		{
			ptr.reset(new ArrayExpressionType(elementType, numElements));
		}
		return *ptr;
	}
	
	StructExpressionType& getStructure(string name)
	{
		unindexedTypes.emplace_back(new StructExpressionType(name));
		return llvm::cast<StructExpressionType>(*unindexedTypes.back());
	}
	
	FunctionExpressionType& getFunction(const ExpressionType& returnType)
	{
		unindexedTypes.emplace_back(new FunctionExpressionType(returnType));
		return llvm::cast<FunctionExpressionType>(*unindexedTypes.back());
	}
	
	size_t size() const
	{
		return 1 + intTypes.size() + pointerTypes.size() + arrayTypes.size() + unindexedTypes.size();
	}
};

void* AstContext::prepareStorageAndUses(unsigned useCount, size_t storage)
{
	size_t useDataSize = sizeof(ExpressionUseArrayHead) + sizeof(ExpressionUse) * useCount;
	size_t totalSize = useDataSize + storage;
	auto pointer = pool.allocateDynamic<char>(totalSize, alignof(void*));
	
	// Prepare use data
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
	
	// The rest of the buffer will be initialized by a placement new
	auto objectStorage = reinterpret_cast<void*>(pointer + useDataSize);
	assert((reinterpret_cast<uintptr_t>(objectStorage) & (alignof(void*) - 1)) == 0);
	
	//errs() << "pointer=" << (void*)pointer << " uses[" << useCount << "]=" << useBegin << " object=" << objectStorage << '\n';
	return objectStorage;
}

AstContext::AstContext(DumbAllocator& pool, Module* module)
: pool(pool)
, module(module)
, types(new TypeIndex)
{
	trueExpr = token(getIntegerType(false, 1), "true");
	falseExpr = token(getIntegerType(false, 1), "false");
	undef = token(getVoid(), "__undefined");
	null = token(getPointerTo(getVoid()), "null");
}

AstContext::~AstContext()
{
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
	
	if (isa<PHINode>(inst))
	{
		Expression* phiOut = expressionFor(inst);
		Expression* phiIn = phiReadsToWrites[phiOut];
		assert(phiIn != nullptr);
		auto assignment = nary(NAryOperatorExpression::Assign, phiOut, phiIn);
		return expr(assignment);
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
	if (unary->getType() == UnaryOperatorExpression::LogicalNegate)
	{
		return unary->getOperand();
	}
	
	if (auto token = dyn_cast<TokenExpression>(expr))
	{
		if (strcmp(token->token, "true") == 0)
		{
			return expressionForFalse();
		}
		if (strcmp(token->token, "false") == 0)
		{
			return expressionForTrue();
		}
	}
	
	return unary(UnaryOperatorExpression::LogicalNegate, expr);
}

Statement* AstContext::append(Statement* a, Statement* b)
{
	if (a == nullptr)
	{
		return b;
	}
	if (b == nullptr)
	{
		return a;
	}
	
	auto seq = sequence();
	if (auto seqA = dyn_cast<SequenceStatement>(a))
	{
		seq->takeAllFrom(*seqA);
	}
	else
	{
		seq->pushBack(a);
	}
	if (auto seqB = dyn_cast<SequenceStatement>(b))
	{
		seq->takeAllFrom(*seqB);
	}
	else
	{
		seq->pushBack(b);
	}
	return seq;
}

ExpressionStatement* AstContext::phiAssignment(PHINode &phi, Value &value)
{
	auto linkedExpression = expressionFor(phi);
	auto& phiWrite = phiReadsToWrites[linkedExpression];
	if (phiWrite == nullptr)
	{
		phiWrite = assignable(getType(*phi.getType()), "phi_in");
	}
	auto assignment = nary(NAryOperatorExpression::Assign, phiWrite, expressionFor(value));
	return expr(assignment);
}

#pragma mark - Types
const ExpressionType& AstContext::getType(Type &type)
{
	if (type.isVoidTy())
	{
		return getVoid();
	}
	else if (auto intTy = dyn_cast<IntegerType>(&type))
	{
		return getIntegerType(false, (unsigned short)intTy->getBitWidth());
	}
	else if (auto ptr = dyn_cast<PointerType>(&type))
	{
		// XXX will break when pointer types lose getElementType
		return getPointerTo(getType(*ptr->getElementType()));
	}
	else if (auto array = dyn_cast<ArrayType>(&type))
	{
		return getArrayOf(getType(*array->getElementType()), array->getNumElements());
	}
	else if (auto funcType = dyn_cast<FunctionType>(&type))
	{
		// We lose parameter names doing this.
		auto& result = createFunction(getType(*funcType->getReturnType()));
		for (Type* param : funcType->params())
		{
			result.append(getType(*param), "");
		}
		return result;
	}
	else if (auto structure = dyn_cast<StructType>(&type))
	{
		auto& structType = structTypeMap[structure];
		if (structType == nullptr)
		{
			string name;
			if (structure->hasName())
			{
				name = structure->getName().str();
				char structPrefix[] = "struct.";
				size_t structPrefixSize = sizeof structPrefix - 1;
				if (name.compare(0, structPrefixSize, structPrefix) == 0)
				{
					name = name.substr(structPrefixSize);
				}
			}
			
			structType = &createStructure(move(name));
			for (unsigned i = 0; i < structure->getNumElements(); ++i)
			{
				string name;
				if (module != nullptr)
				{
					name = md::getRecoveredReturnFieldName(*module, *structure, i).str();
				}
				if (name.size() == 0)
				{
					raw_string_ostream(name) << "field" << i;
				}
				structType->append(getType(*structure->getElementType(i)), name);
			}
		}
		return *structType;
	}
	else
	{
		llvm_unreachable("unknown LLVM type");
	}
}

const VoidExpressionType& AstContext::getVoid()
{
	return types->getVoid();
}

const IntegerExpressionType& AstContext::getIntegerType(bool isSigned, unsigned short numBits)
{
	return types->getIntegerType(isSigned, numBits);
}

const PointerExpressionType& AstContext::getPointerTo(const ExpressionType& pointee)
{
	return types->getPointerTo(pointee);
}

const ArrayExpressionType& AstContext::getArrayOf(const ExpressionType& elementType, size_t numElements)
{
	return types->getArrayOf(elementType, numElements);
}

StructExpressionType& AstContext::createStructure(string name)
{
	return types->getStructure(move(name));
}

FunctionExpressionType& AstContext::createFunction(const ExpressionType &returnType)
{
	return types->getFunction(returnType);
}
