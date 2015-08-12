//
// function.cpp
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

#include "function.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <iostream>
#include <memory>

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
}

void FunctionNode::printIntegerConstant(llvm::raw_ostream &os, uint64_t integer)
{
	if (integer > 0xffff)
	{
		(os << "0x").write_hex(integer);
	}
	else
	{
		os << integer;
	}
}

void FunctionNode::printIntegerConstant(llvm::raw_ostream &&os, uint64_t integer)
{
	printIntegerConstant(os, integer);
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

std::string FunctionNode::createName(const string& prefix) const
{
	string declName;
	printIntegerConstant(raw_string_ostream(declName) << prefix, declarations.size());
	return declName;
}

Expression* FunctionNode::createDeclaration(Type &type)
{
	return createDeclaration(type, createName("anon"));
}

Expression* FunctionNode::createDeclaration(Type &type, const string& declName)
{
	auto identifier = pool.allocate<TokenExpression>(pool, declName);
	auto typeToken = pool.allocate<TokenExpression>(pool, toString(&type));
	auto declaration = pool.allocate<DeclarationNode>(typeToken, identifier);
	declaration->orderHint = numeric_limits<size_t>::max() - declarations.size();
	declarations.push_back(declaration);
	return identifier;
}

Expression* FunctionNode::lvalueFor(llvm::Value &value)
{
	auto iter = lvalueMap.find(&value);
	if (iter == lvalueMap.end())
	{
		Expression* expr = valueFor(value);
		if (!isa<PHINode>(value) && !isa<AllocaInst>(value))
		{
			expr = pool.allocate<UnaryOperatorExpression>(UnaryOperatorExpression::Dereference, expr);
		}
		iter = lvalueMap.insert({&value, expr}).first;
	}
	return iter->second;
}

Expression* FunctionNode::valueFor(llvm::Value &value)
{
	auto pointer = &value;
	auto iter = valueMap.find(pointer);
	if (iter != valueMap.end())
	{
		return iter->second;
	}
	
	Expression* result;
	if (auto constant = dyn_cast<Constant>(pointer))
	{
		if (auto constantInt = dyn_cast<ConstantInt>(constant))
		{
			result = pool.allocate<NumericExpression>(constantInt->getLimitedValue());
		}
		else if (auto expression = dyn_cast<ConstantExpr>(constant))
		{
			unique_ptr<Instruction> asInst(expression->getAsInstruction());
			result = valueFor(*asInst);
			valueMap.erase(asInst.get());
		}
		else if (isa<UndefValue>(constant))
		{
			result = TokenExpression::undefExpression;
		}
		else
		{
			llvm_unreachable("unexpected constant type");
		}
	}
	else if (isa<Argument>(value))
	{
		result = pool.allocate<TokenExpression>(pool, value.getName().str());
	}
	else if (isa<PHINode>(value))
	{
		result = createDeclaration(*value.getType(), createName("phi"));
	}
	else if (isa<AllocaInst>(value))
	{
		result = createDeclaration(*value.getType(), createName("alloca"));
	}
	else if (auto load = dyn_cast<LoadInst>(&value))
	{
		result = lvalueFor(*load->getPointerOperand());
	}
	else if (auto call = dyn_cast<CallInst>(&value))
	{
		auto function = pool.allocate<TokenExpression>(pool, call->getCalledFunction()->getName().str());
		auto callExpr = pool.allocate<CallExpression>(pool, function);
		for (unsigned i = 0; i < call->getNumArgOperands(); i++)
		{
			auto operand = call->getArgOperand(i);
			callExpr->parameters.push_back(valueFor(*operand));
		}
		result = callExpr;
	}
	else if (auto binOp = dyn_cast<BinaryOperator>(&value))
	{
		auto left = valueFor(*binOp->getOperand(0));
		auto right = valueFor(*binOp->getOperand(1));
		result = pool.allocate<NAryOperatorExpression>(pool, getOperator(binOp->getOpcode()), left, right);
	}
	else if (auto cmp = dyn_cast<CmpInst>(pointer))
	{
		auto left = valueFor(*cmp->getOperand(0));
		auto right = valueFor(*cmp->getOperand(1));
		result = pool.allocate<NAryOperatorExpression>(pool, getOperator(cmp->getPredicate()), left, right);
	}
	else if (auto cast = dyn_cast<CastInst>(pointer))
	{
		auto type = pool.allocate<TokenExpression>(pool, toString(cast->getDestTy()));
		result = pool.allocate<CastExpression>(type, valueFor(*cast->getOperand(0)));
	}
	else if (auto ternary = dyn_cast<SelectInst>(pointer))
	{
		auto condition = valueFor(*ternary->getCondition());
		auto ifTrue = valueFor(*ternary->getTrueValue());
		auto ifFalse = valueFor(*ternary->getFalseValue());
		result = pool.allocate<TernaryExpression>(condition, ifTrue, ifFalse);
	}
	else
	{
		llvm_unreachable("unexpected value type");
	}
	
	valueMap.insert({&value, result});
	return result;
}

Statement* FunctionNode::statementFor(llvm::Instruction &inst)
{
	Statement* result;
	// Special treatment for non-value instructions (instructions that can't be used as another value).
	if (auto store = dyn_cast<StoreInst>(&inst))
	{
		Expression* location = lvalueFor(*store->getPointerOperand());
		Expression* storeValue = valueFor(*store->getValueOperand());
		result = pool.allocate<AssignmentNode>(location, storeValue);
	}
	else if (auto call = dyn_cast<CallInst>(&inst))
	{
		Expression* callExpr = valueFor(*call);
		if (call->getNumUses() > 0)
		{
			Expression* assignTo = createDeclaration(*call->getType());
			result = pool.allocate<AssignmentNode>(assignTo, callExpr);
		}
		else
		{
			result = pool.allocate<ExpressionNode>(callExpr);
		}
	}
	else if (auto terminator = dyn_cast<TerminatorInst>(&inst))
	{
		if (auto ret = dyn_cast<ReturnInst>(terminator))
		{
			auto returnStatement = pool.allocate<KeywordNode>("return");
			if (auto retVal = ret->getReturnValue())
			{
				returnStatement->operand = valueFor(*retVal);
			}
			result = returnStatement;
		}
		else
		{
			return nullptr;
		}
	}
	else if (isa<PHINode>(&inst))
	{
		// Speical case for PHI nodes, since they don't translate into a statement at the place LLVM defines them.
		result = nullptr;
	}
	else
	{
		auto value = valueFor(inst);
		auto identifier = createDeclaration(*inst.getType());
		result = pool.allocate<AssignmentNode>(identifier, value);
	}
	
	if (auto assignment = dyn_cast_or_null<AssignmentNode>(result))
	{
		valueMap[&inst] = assignment->left;
	}
	
	return result;
}

SequenceNode* FunctionNode::basicBlockToStatement(llvm::BasicBlock &bb)
{
	SequenceNode* node = pool.allocate<SequenceNode>(pool);
	// Translate instructions.
	for (Instruction& inst : bb)
	{
		if (Statement* statement = statementFor(inst))
		{
			node->statements.push_back(statement);
		}
	}
	
	// Add phi value assignments.
	for (BasicBlock* successor : successors(&bb))
	{
		for (auto phiIter = successor->begin(); PHINode* phi = dyn_cast<PHINode>(phiIter); phiIter++)
		{
			auto assignTo = lvalueFor(*phi);
			auto phiValue = valueFor(*phi->getIncomingValueForBlock(&bb));
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
	
	// Print declarations. Sort to new container.
	vector<DeclarationNode*> decls(declarations.begin(), declarations.end());
	if (decls.size() > 0)
	{
		sort(decls.begin(), decls.end(), [](DeclarationNode* a, DeclarationNode* b)
		{
			return a->orderHint < b->orderHint;
		});
		
		for (auto declaration : decls)
		{
			declaration->print(os, 1);
		}
		
		os << nl;
	}
	
	// print body
	if (auto seq = dyn_cast<SequenceNode>(body))
	{
		for (auto statement : seq->statements)
		{
			statement->print(os, 1);
		}
	}
	else
	{
		body->print(os, 1);
	}
	
	os << "}\n";
}

void FunctionNode::dump() const
{
	raw_os_ostream rerr(cerr);
	print(rerr);
}

