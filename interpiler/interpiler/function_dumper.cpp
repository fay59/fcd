//
//  function_dumper.cpp
//  interpiler
//
//  Created by Félix on 2015-04-13.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

// haxx
#include <cxxabi.h>
#include <dlfcn.h>
#include <iostream>

#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Operator.h>
#include <unordered_map>

#include "dump_constant.h"
#include "function_dumper.h"

using namespace llvm;
using namespace std;

#define ENUM_STRING(x) [(size_t)x] = "llvm::" #x

namespace
{
	constexpr char nl = '\n';
	constexpr char tab = '\t';
	
	string predicates[] = {
		ENUM_STRING(CmpInst::FCMP_FALSE),
		ENUM_STRING(CmpInst::FCMP_OEQ),
		ENUM_STRING(CmpInst::FCMP_OGT),
		ENUM_STRING(CmpInst::FCMP_OGE),
		ENUM_STRING(CmpInst::FCMP_OLT),
		ENUM_STRING(CmpInst::FCMP_OLE),
		ENUM_STRING(CmpInst::FCMP_ONE),
		ENUM_STRING(CmpInst::FCMP_ORD),
		ENUM_STRING(CmpInst::FCMP_UNO),
		ENUM_STRING(CmpInst::FCMP_UEQ),
		ENUM_STRING(CmpInst::FCMP_UGT),
		ENUM_STRING(CmpInst::FCMP_UGE),
		ENUM_STRING(CmpInst::FCMP_ULT),
		ENUM_STRING(CmpInst::FCMP_ULE),
		ENUM_STRING(CmpInst::FCMP_UNE),
		ENUM_STRING(CmpInst::FCMP_TRUE),
		ENUM_STRING(CmpInst::ICMP_EQ),
		ENUM_STRING(CmpInst::ICMP_NE),
		ENUM_STRING(CmpInst::ICMP_UGT),
		ENUM_STRING(CmpInst::ICMP_UGE),
		ENUM_STRING(CmpInst::ICMP_ULT),
		ENUM_STRING(CmpInst::ICMP_ULE),
		ENUM_STRING(CmpInst::ICMP_SGT),
		ENUM_STRING(CmpInst::ICMP_SGE),
		ENUM_STRING(CmpInst::ICMP_SLT),
		ENUM_STRING(CmpInst::ICMP_SLE),
	};
	
	string binaryOps[] = {
		ENUM_STRING(BinaryOperator::Add),
		ENUM_STRING(BinaryOperator::FAdd),
		ENUM_STRING(BinaryOperator::Sub),
		ENUM_STRING(BinaryOperator::FSub),
		ENUM_STRING(BinaryOperator::Mul),
		ENUM_STRING(BinaryOperator::FMul),
		ENUM_STRING(BinaryOperator::UDiv),
		ENUM_STRING(BinaryOperator::SDiv),
		ENUM_STRING(BinaryOperator::FDiv),
		ENUM_STRING(BinaryOperator::URem),
		ENUM_STRING(BinaryOperator::SRem),
		ENUM_STRING(BinaryOperator::FRem),
		ENUM_STRING(BinaryOperator::Shl),
		ENUM_STRING(BinaryOperator::LShr),
		ENUM_STRING(BinaryOperator::AShr),
		ENUM_STRING(BinaryOperator::And),
		ENUM_STRING(BinaryOperator::Or),
		ENUM_STRING(BinaryOperator::Xor),
	};
	
	class to_string_visitor : public llvm::InstVisitor<to_string_visitor>
	{
		raw_ostream& os;
		type_dumper& types;
		global_dumper& globals;
		unordered_map<const BasicBlock*, size_t> blockIndices;
		unordered_map<const Value*, string> valueNames;
		
		const string& name_of(Value* v)
		{
			auto iter = valueNames.find(v);
			assert(iter != valueNames.end());
			return iter->second;
		}
	
		string make_prefix(const string& name)
		{
			string prefix;
			raw_string_ostream prefixStream(prefix);
			(prefixStream << name << valueNames.size() << "_").flush();
			return prefix;
		}
		
		raw_ostream& declare(const string& type, const string& name, bool equals = true)
		{
			return os << '\t' << "llvm::" << type << " " << name << (equals ? " = " : " ");
		}
		
		raw_ostream& declare(const string& name)
		{
			return declare("Value*", name);
		}
		
		template<typename T>
		raw_ostream& declare(const string& type, const string& prefix, T&& append, bool equals = true)
		{
			return os << '\t' << "llvm::" << type << " " << prefix << append << (equals ? " = " : " ");
		}
		
		void ensure_exists(llvm::Value* v, const string& prefix)
		{
			Constant* c = dyn_cast<Constant>(v);
			auto nameIter = valueNames.find(v);
			if (nameIter == valueNames.end())
			{
				if (auto g = dyn_cast<GlobalVariable>(v))
				{
					size_t globalIndex = globals.accumulate(g);
					string identifier;
					raw_string_ostream ss(identifier);
					(ss << "globals[" << globalIndex << "]").flush();
					valueNames.insert(make_pair(v, identifier));
				}
				else if (auto f = dyn_cast<Function>(v))
				{
					size_t globalIndex = globals.accumulate(f);
					string identifier;
					raw_string_ostream ss(identifier);
					(ss << "globals[" << globalIndex << "]").flush();
					valueNames.insert(make_pair(v, identifier));
				}
				else if (auto e = dyn_cast<ConstantExpr>(v))
				{
					Instruction* i = e->getAsInstruction();
					visit(i);
					valueNames.insert(make_pair(e, name_of(i)));
					valueNames.erase(i);
					delete i;
				}
				else if (c != nullptr)
				{
					string argNumPrefix = prefix;
					raw_string_ostream ss(argNumPrefix);
					(ss << "val" << valueNames.size() << "_").flush();
					string identifier = dump_constant(os, types, argNumPrefix, c);
					valueNames.insert(make_pair(v, identifier));
				}
				else
				{
					assert(!"not implemented");
				}
			}
		}
		
	public:
		to_string_visitor(raw_ostream& os, type_dumper& types, global_dumper& globals, const iplist<Argument>& arguments, const iplist<BasicBlock>& blocks)
		: os(os), types(types), globals(globals)
		{
			for (const BasicBlock& bb : blocks)
			{
				size_t blockIndex = blockIndices.size();
				declare("BasicBlock", "block", blockIndex) << "llvm::BasicBlock::Create(context, \"\", function);" << nl;
				blockIndices.insert(make_pair(&bb, blockIndex));
			}
			
			size_t count = 0;
			for (const Argument& arg : arguments)
			{
				string argName;
				raw_string_ostream ss(argName);
				ss << "arg" << count;
				ss.flush();
				valueNames.insert(make_pair(&arg, argName));
				count++;
			}
		}
		
		void visitBasicBlock(BasicBlock& bb)
		{
			auto iter = blockIndices.find(&bb);
			assert(iter != blockIndices.end());
			os << nl << tab << "builder.SetInsertPoint(block" << iter->second << ");" << nl;
		}
		
		void visitReturnInst(ReturnInst& i)
		{
			// This assumes just one ret per function. Otherwise it's gonna generate broken code, with a return statement
			// before the end of the function.
			os << tab << "return";
			if (Value* v = i.getReturnValue())
			{
				os << " " << name_of(v);
			}
			os << ';' << nl;
		}
		
		void visitGetElementPtrInst(GetElementPtrInst& i)
		{
			string prefix = make_prefix("gep");
			Value* pointerOperand = i.getPointerOperand();
			ensure_exists(pointerOperand, prefix);
			for (auto iter = i.idx_begin(); iter != i.idx_end(); iter++)
			{
				ensure_exists(iter->get(), prefix);
			}
			
			declare("ArrayRef<llvm::Value*> ", prefix, "array", false) << "{ ";
			for (auto iter = i.idx_begin(); iter != i.idx_end(); iter++)
			{
				os << name_of(iter->get()) << ", ";
			}
			os << "};" << nl;
			
			string name = prefix + "var";
			declare(name) << "builder.Create";
			if (i.isInBounds())
			{
				os << "InBounds";
			}
			os << "GEP(" << valueNames[pointerOperand] << ", " << prefix << "array);" << nl;
			valueNames.insert(make_pair(&i, name));
		}
		
		void visitLoadInst(LoadInst& i)
		{
			string prefix = make_prefix("load");
			
			Value* pointer = i.getPointerOperand();
			ensure_exists(pointer, prefix);
			
			string varName = prefix + "var";
			declare(varName) << "builder.CreateLoad(" << name_of(pointer) << ", " << i.isVolatile() << ");" << nl;
			valueNames.insert(make_pair(&i, varName));
		}
		
		void visitStoreInst(StoreInst& i)
		{
			string prefix = make_prefix("store");
			
			Value* pointer = i.getPointerOperand();
			Value* value = i.getValueOperand();
			ensure_exists(pointer, prefix);
			ensure_exists(value, prefix);
			
			string varName = prefix + "var";
			declare(varName) << "builder.CreateStore(" << name_of(value) << ", " << name_of(pointer) << ", " << i.isVolatile() << ");" << nl;
			valueNames.insert(make_pair(&i, varName));
		}
		
		void visitCmpInst(CmpInst& i)
		{
			string prefix = make_prefix("cmp");
			
			Value* left = i.getOperand(0);
			Value* right = i.getOperand(1);
			ensure_exists(left, prefix);
			ensure_exists(right, prefix);
			
			string varName = prefix + "var";
			declare(varName) << "builder.Create";
			if (i.isIntPredicate())
			{
				os << 'I';
			}
			else if (i.isFPPredicate())
			{
				os << 'F';
			}
			else
			{
				assert(!"not implemented");
			}
			
			CmpInst::Predicate pred = i.getPredicate();
			os << "Cmp(" << predicates[pred] << ", " << name_of(left) << ", " << name_of(right) << ");" << nl;
			valueNames.insert(make_pair(&i, varName));
		}
		
		void visitBranchInst(BranchInst& i)
		{
			string prefix = make_prefix("cmp");
			os << tab << "builder.Create";
			if (i.isConditional())
			{
				auto value = i.getCondition();
				ensure_exists(value, prefix);
				os << "CondBr(" << name_of(value) << ", ";
				os << "block" << blockIndices[i.getSuccessor(0)] << ", ";
				os << "block" << blockIndices[i.getSuccessor(1)];
			}
			else
			{
				os << "Br(block" << blockIndices[i.getSuccessor(0)];
			}
			os << ");" << nl;
		}
		
		void visitCallInst(CallInst& i)
		{
			string prefix = make_prefix("call");
			
			// call
			Value* called = i.getCalledValue();
			if (Function* f = dyn_cast<Function>(called))
			{
				assert(f->isDeclaration() && "can't call non-inline functions");
			}
			
			ensure_exists(called, prefix);
			
			for (Use& use : i.arg_operands())
			{
				Value* arg = use.get();
				ensure_exists(arg, prefix);
			}
			
			string varName = prefix + "var";
			unsigned numArgs = i.getNumArgOperands();
			if (numArgs <= 5)
			{
				declare(varName) << "builder.CreateCall";
				if (numArgs > 1)
				{
					os << numArgs;
				}
				os << "(" << name_of(called);
				for (Use& use : i.arg_operands())
				{
					Value* arg = use.get();
					os << ", " << name_of(arg);
				}
				os << ");" << nl;
			}
			else
			{
				os << tab << "llvm::Array<Value*> " << prefix << "array { ";
				for (Use& use : i.arg_operands())
				{
					Value* arg = use.get();
					os << name_of(arg) << ", ";
				}
				os << "};" << nl;
				
				declare(varName) << "builder.CreateCall(" << name_of(called) << ", " << prefix << "array);" << nl;
			}
			valueNames.insert(make_pair(&i, varName));
		}
		
		void visitUnreachableInst(UnreachableInst&)
		{
			os << '\t' << "builder.CreateUnreachable();" << nl;
		}
		
		void visitBinaryOperator(BinaryOperator& i)
		{
			string prefix = make_prefix("binop");
			Value* left = i.getOperand(0);
			Value* right = i.getOperand(1);
			ensure_exists(left, prefix);
			ensure_exists(right, prefix);
			
			unsigned opcode = i.getOpcode();
			string varName = prefix + "var";
			declare(varName) << "llvm::BinaryOperator::Create";
			if (PossiblyExactOperator::isPossiblyExactOpcode(opcode) && i.isExact())
			{
				os << "Exact";
			}
			else if (i.hasNoSignedWrap())
			{
				os << "NSW";
			}
			else if (i.hasNoUnsignedWrap())
			{
				os << "NUW";
			}
			os << "(" << binaryOps[opcode] << ", " << name_of(left) << ", " << name_of(right) << ");" << nl;
			valueNames.insert(make_pair(&i, varName));
		}
		
		// not implemented
		void visitInstruction(Instruction& i)
		{
			os.flush();
			
			// Because just looking at the stack trace is too mainstream.
			const void* ptr = __builtin_return_address(0);
			Dl_info sym;
			if (dladdr(ptr, &sym))
			{
				int status;
				if (auto mem = unique_ptr<char[], void (*)(void*)>(abi::__cxa_demangle(sym.dli_sname, nullptr, nullptr, &status), &free))
				{
					string name = mem.get();
					size_t parenIndex = name.find_last_of('(');
					cout << "You need to implement the function for ";
					cout << name.substr(parenIndex + 1 + 6, name.length() - parenIndex - 3 - 6) << endl;
					abort();
				}
			}
			cout << "look at the stack trace" << endl;
			abort();
		}
	};
}



string function_dumper::make_function(llvm::Function *function, const std::string &prototype)
{
	string result;
	raw_string_ostream ss(result);
	
	ss << prototype << nl << '{' << nl;
	
	to_string_visitor visitor(ss, types, globals, function->getArgumentList(), function->getBasicBlockList());
	visitor.visit(function->begin(), function->end());
	
	ss << '}' << nl;
	ss.flush();
	return result;
}

function_dumper::function_dumper(LLVMContext& ctx, type_dumper& types, global_dumper& globals)
: body(prototypes_body), types(types), globals(globals), context(ctx)
{
}

unique_ptr<string> function_dumper::accumulate(llvm::Function *function)
{
	string prototype;
	raw_string_ostream prototypeStream(prototype);
	
	Type* returnType = function->getReturnType();
	Type* voidTy = Type::getVoidTy(context);
	
	if (returnType == voidTy)
	{
		prototypeStream << "void";
	}
	else
	{
		prototypeStream << "llvm::Value*";
	}
	prototypeStream << ' ' << function->getName() << '(';
	
	const auto& argList = function->getArgumentList();
	for (size_t i = 0; i < argList.size(); i++)
	{
		if (i != 0)
		{
			prototypeStream << ", ";
		}
		prototypeStream << "llvm::Value* arg" << i;
	}
	prototypeStream << ")";
	prototypeStream.flush();
	
	if (known_functions.count(function) == 0)
	{
		body << prototype << ";" << nl;
		known_functions.insert(function);
	}
	
	if (function->isDeclaration())
	{
		return nullptr;
	}
	
	return make_unique<string>(make_function(function, prototype));
}
