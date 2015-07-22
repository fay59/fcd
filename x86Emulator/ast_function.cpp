//
//  ast_function.cpp
//  x86Emulator
//
//  Created by Félix on 2015-07-20.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#include "ast_function.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <iostream>

using namespace llvm;
using namespace std;

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
			// HACKHACK: this will not do if we ever want to differentiate signed and unsigned values
			os << "int" << type->getIntegerBitWidth() << "_t";
			return;
		}
		if (type->isPointerTy())
		{
			// HACKHACK: this will not do once LLVM gets rid of pointer types
			printTypeAsC(os, type->getPointerElementType());
			os << '*';
			return;
		}
		llvm_unreachable("implement me");
	}
	
	inline string toString(size_t integer)
	{
		string result;
		raw_string_ostream(result) << integer;
		return result;
	}
	
	inline string toString(Type* type)
	{
		string result;
		raw_string_ostream ss(result);
		printTypeAsC(ss, type);
		ss.flush();
		return result;
	}
	
	inline bool getOffsetFromOperand1(Argument& sp, BinaryOperator& op, int64_t& spOffset)
	{
		if (op.getOperand(0) == &sp)
		{
			if (auto constant = dyn_cast<ConstantInt>(op.getOperand(1)))
			{
				spOffset = static_cast<int64_t>(constant->getLimitedValue());
				return true;
			}
		}
		return false;
	}
	
	constexpr char nl = '\n';
	constexpr size_t localVarBaseHint = numeric_limits<size_t>::max() ^ (numeric_limits<size_t>::max() >> 1); // only the most significant bit set
	
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
	
	struct erase_inst
	{
		Instruction* inst;
		erase_inst(Instruction* inst) : inst(inst)
		{
		}
		~erase_inst()
		{
			delete inst;
		}
	};
}

void FunctionNode::printPrototype(llvm::raw_ostream &os, llvm::Function &function)
{
	auto type = function.getFunctionType();
	printTypeAsC(os, type->getReturnType());
	os << ' ' << function.getName() << '(';
	auto iter = function.arg_begin();
	if (iter != function.arg_end())
	{
		printTypeAsC(os, iter->getType());
		StringRef argName = iter->getName();
		if (argName != "")
		{
			os << ' ' << iter->getName();
		}
		iter++;
		while (iter != function.arg_end())
		{
			os << ", ";
			printTypeAsC(os, iter->getType());
			argName = iter->getName();
			if (argName != "")
			{
				os << ' ' << iter->getName();
			}
			iter++;
		}
		
		if (function.isVarArg())
		{
			os << ", ";
		}
	}
	else
	{
		os << "void";
	}
	
	if (function.isVarArg())
	{
		os << "...";
	}
	
	os << ')';
}

void FunctionNode::identifyLocals(llvm::Argument& stackPointer)
{
	Value* spValue = &stackPointer;
	if (isa<PointerType>(stackPointer.getType()))
	{
		// Preservation couldn't be proved for this function. There should be a `load` very early, though.
		spValue = nullptr;
		for (Use& use : stackPointer.uses())
		{
			if (auto load = dyn_cast<LoadInst>(use.getUser()))
			{
				if (spValue == nullptr)
				{
					spValue = load;
				}
				else
				{
					assert(!"Loading stack pointer multiple times, this is weird");
				}
			}
		}
	}
	
	for (Use& use : spValue->uses())
	{
		auto operationOnSp = use.getUser();
		for (Use& opUse : operationOnSp->uses())
		{
			if (auto castInst = dyn_cast<IntToPtrInst>(opUse.getUser()))
			{
				// Make castInst a local.
				if (auto binOp = dyn_cast<BinaryOperator>(operationOnSp))
				{
					int64_t spOffset = 0;
					bool hasSpOffset = false;
					if (binOp->getOpcode() == BinaryOperator::Add)
					{
						hasSpOffset = getOffsetFromOperand1(stackPointer, *binOp, spOffset);
					}
					else if (binOp->getOpcode() == BinaryOperator::Sub)
					{
						hasSpOffset = getOffsetFromOperand1(stackPointer, *binOp, spOffset);
						spOffset = -spOffset;
					}
					
					if (hasSpOffset)
					{
						string varName;
						raw_string_ostream ss(varName);
						if (spOffset <= 0)
						{
							ss << 'm' << -spOffset;
						}
						else
						{
							ss << 'p' << spOffset;
						}
						ss.flush();
						
						string comment;
						raw_string_ostream commentSS(comment);
						commentSS << "local: sp" << (spOffset < 0 ? "" : "+") << spOffset;
						commentSS.flush();
						
						// HACKHACK: bypassing type analysis
						auto typeToken = pool.allocate<TokenExpression>(pool, "integer");
						auto nameToken = pool.allocate<TokenExpression>(pool, varName);
						const char* commentValue = pool.copy(comment.c_str(), comment.length() + 1);
						auto decl = pool.allocate<DeclarationNode>(typeToken, nameToken, commentValue);
						decl->orderHint = localVarBaseHint + spOffset;
						
						declarations.push_back(decl);
						valueMap.insert({castInst, nameToken});
						valuesWithDeclaration.insert(castInst);
					}
				}
			}
		}
	}
}

Expression* FunctionNode::createDeclaration(Value& value)
{
	return createDeclaration(value, "anon" + toString(declarations.size()));
}

Expression* FunctionNode::createDeclaration(Value& value, const std::string &name)
{
	auto result = pool.allocate<TokenExpression>(pool, name);
	auto typeExpr = pool.allocate<TokenExpression>(pool, toString(value.getType()));
	auto decl = pool.allocate<DeclarationNode>(typeExpr, result);
	decl->orderHint = numeric_limits<size_t>::max() - declarations.size();
	declarations.push_back(decl);
	valueMap.insert({&value, result});
	valuesWithDeclaration.insert(&value);
	return result;
}

Expression* FunctionNode::getValueFor(llvm::Value& value)
{
	auto pointer = &value;
	auto iter = valueMap.find(pointer);
	if (iter != valueMap.end())
	{
		return iter->second;
	}
	
	if (auto constantInt = dyn_cast<ConstantInt>(pointer))
	{
		TokenExpression* result = pool.allocate<TokenExpression>(pool, toString(constantInt->getLimitedValue()));
		valueMap.insert({constantInt, result});
		return result;
	}
	else if (isa<Argument>(value))
	{
		TokenExpression* argExpression = pool.allocate<TokenExpression>(pool, value.getName().str());
		valueMap.insert({pointer, argExpression});
		return argExpression;
	}
	else if (isa<PHINode>(value))
	{
		return createDeclaration(value, "phi" + toString(declarations.size()));
	}
	else
	{
		erase_inst maybeErase(nullptr);
		if (isa<UndefValue>(pointer))
		{
			return TokenExpression::undefExpression;
		}
		else if (auto constant = dyn_cast<ConstantExpr>(pointer))
		{
			maybeErase.inst = constant->getAsInstruction();
			pointer = maybeErase.inst;
		}
		
		if (auto binOp = dyn_cast<BinaryOperator>(pointer))
		{
			auto left = getValueFor(*binOp->getOperand(0));
			auto right = getValueFor(*binOp->getOperand(1));
			return pool.allocate<NAryOperatorExpression>(pool, getOperator(binOp->getOpcode()), left, right);
		}
		else if (auto cmp = dyn_cast<CmpInst>(pointer))
		{
			auto left = getValueFor(*cmp->getOperand(0));
			auto right = getValueFor(*cmp->getOperand(1));
			return pool.allocate<NAryOperatorExpression>(pool, getOperator(cmp->getPredicate()), left, right);
		}
		else if (auto cast = dyn_cast<CastInst>(pointer))
		{
			auto type = pool.allocate<TokenExpression>(pool, toString(cast->getDestTy()));
			return pool.allocate<CastExpression>(type, getValueFor(*cast->getOperand(0)));
		}
	}
	
	llvm_unreachable("implement me");
}

Expression* FunctionNode::getLvalueFor(llvm::Value &value)
{
	if (isa<PHINode>(value) || valuesWithDeclaration.count(&value) != 0)
	{
		return getValueFor(value);
	}
	if (isa<Argument>(value))
	{
		return pool.allocate<UnaryOperatorExpression>(UnaryOperatorExpression::Dereference, getValueFor(value));
	}
	
	// pretend that it's a pointer then...
	return pool.allocate<UnaryOperatorExpression>(UnaryOperatorExpression::Dereference, getValueFor(value));
}

SequenceNode* FunctionNode::basicBlockToStatement(llvm::BasicBlock &bb)
{
	SequenceNode* node = pool.allocate<SequenceNode>(pool);
	// Translate instructions.
	for (Instruction& inst : bb)
	{
		// Load, store and call instructions have side effects and cannot be moved around.
		// Arguments to these, however, can be lazily rendered to C.
		if (auto load = dyn_cast<LoadInst>(&inst))
		{
			Expression* assignTo = createDeclaration(*load);
			Expression* dereferenced = getLvalueFor(*load->getPointerOperand());
			auto assignment = pool.allocate<AssignmentNode>(assignTo, dereferenced);
			node->statements.push_back(assignment);
		}
		else if (auto store = dyn_cast<StoreInst>(&inst))
		{
			Value& stored = *store->getValueOperand();
			Expression* dereferenced = getLvalueFor(*store->getPointerOperand());
			auto value = getValueFor(stored);
			auto assignment = pool.allocate<AssignmentNode>(dereferenced, value);
			node->statements.push_back(assignment);
		}
		else if (auto call = dyn_cast<CallInst>(&inst))
		{
			auto function = pool.allocate<TokenExpression>(pool, call->getCalledFunction()->getName().str());
			auto callExpr = pool.allocate<CallExpression>(pool, function);
			for (unsigned i = 0; i < call->getNumArgOperands(); i++)
			{
				auto operand = call->getArgOperand(i);
				callExpr->parameters.push_back(getValueFor(*operand));
			}
			
			if (call->getNumUses() > 0)
			{
				Expression* assignTo = createDeclaration(*call);
				auto assignment = pool.allocate<AssignmentNode>(assignTo, callExpr);
				node->statements.push_back(assignment);
			}
			else
			{
				auto callNode = pool.allocate<ExpressionNode>(callExpr);
				node->statements.push_back(callNode);
			}
		}
		else if (auto ret = dyn_cast<ReturnInst>(&inst))
		{
			auto returnStatement = pool.allocate<KeywordNode>("return");
			if (auto retVal = ret->getReturnValue())
			{
				returnStatement->operand = getValueFor(*retVal);
			}
			node->statements.push_back(returnStatement);
		}
		else if (inst.getNumUses() > 1 && getLvalueFor(inst) == nullptr)
		{
			// might as well make it a local
			auto value = getValueFor(inst);
			auto assignTo = createDeclaration(inst);
			auto assignment = pool.allocate<AssignmentNode>(assignTo, value);
			node->statements.push_back(assignment);
		}
	}
	
	// Add phi value assignments.
	for (BasicBlock* successor : successors(&bb))
	{
		for (auto phiIter = successor->begin(); PHINode* phi = dyn_cast<PHINode>(phiIter); phiIter++)
		{
			auto assignTo = getLvalueFor(*phi);
			auto phiValue = getValueFor(*phi->getIncomingValueForBlock(&bb));
			auto assignment = pool.allocate<AssignmentNode>(assignTo, phiValue);
			node->statements.push_back(assignment);
		}
	}
	
	return node;
}

void FunctionNode::print(llvm::raw_ostream &os) const
{
	printPrototype(os, function);
	os << "\n{\n";
	
	// print declarations
	vector<Statement*> decls(declarations.begin(), declarations.end());
	sort(decls.begin(), decls.end(), [](Statement* a, Statement* b)
	{
		return cast<DeclarationNode>(a)->orderHint < cast<DeclarationNode>(b)->orderHint;
	});
	
	for (auto declaration : decls)
	{
		declaration->print(os, 1);
	}
	
	os << nl;
	// print body
	for (auto statement : body->statements)
	{
		statement->print(os, 1);
	}
	
	os << "}\n";
}

void FunctionNode::dump() const
{
	raw_os_ostream rerr(cerr);
	print(rerr);
}

