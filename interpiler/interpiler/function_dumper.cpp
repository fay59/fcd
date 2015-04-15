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
#include <stdexcept>
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
	
#define LOOKUP_TABLE_ELEMENT(x, name, enum) [x] = "llvm::Instruction::" #name
	
#define  FIRST_BINARY_INST(x)				string binaryOps[] = {
#define HANDLE_BINARY_INST(x, name, enum)		LOOKUP_TABLE_ELEMENT(x, name, enum),
#define   LAST_BINARY_INST(x)				};
#include "llvm/IR/Instruction.def"
	
#define  FIRST_CAST_INST(x)					string castOps[] = {
#define HANDLE_CAST_INST(x, name, enum)			LOOKUP_TABLE_ELEMENT(x, name, enum),
#define   LAST_CAST_INST(x)					};
#include "llvm/IR/Instruction.def"
	
	pair<bool (CallInst::*)() const, string> callInstAttributes[] = {
		make_pair(&CallInst::isNoInline, "setNoInline"),
		make_pair(&CallInst::isTailCall, "setTailCall"),
		make_pair(&CallInst::canReturnTwice, "setCanReturnTwice"),
		make_pair(&CallInst::doesNotAccessMemory, "setDoesNotAccessMemory"),
		make_pair(&CallInst::onlyReadsMemory, "setOnlyReadsMemory"),
		make_pair(&CallInst::doesNotReturn, "setDoesNotReturn"),
		make_pair(&CallInst::doesNotThrow, "setDoesNotThrow"),
		make_pair(&CallInst::cannotDuplicate, "setCannotDuplicate"),
	};
	
	class to_string_visitor : public llvm::InstVisitor<to_string_visitor>
	{
		raw_ostream& os;
		type_dumper& types;
		global_dumper& globals;
		unordered_map<const BasicBlock*, size_t> blockIndices;
		unordered_map<const Value*, string> valueNames;
		
#if DEBUG
		unordered_set<string> usedNames;
		void set_name(const Value* value, const std::string& name)
		{
			assert(usedNames.count(name) == 0);
			assert(valueNames.count(value) == 0);
			valueNames.insert(make_pair(value, name));
		}
#else
		void set_name(const Value* value, const std::string& name)
		{
			assert(valueNames.count(value) == 0);
			valueNames.insert(make_pair(value, name));
		}
#endif
		
		void set_name(const Value& value, const std::string& name)
		{
			set_name(&value, name);
		}
		
		const string& name_of(Value* v)
		{
			auto iter = valueNames.find(v);
			assert(iter != valueNames.end());
			return iter->second;
		}
		
		string name_of(BasicBlock* bb)
		{
			auto iter = blockIndices.find(bb);
			assert(iter != blockIndices.end());
			
			string result;
			(raw_string_ostream(result) << "block" << iter->second).flush();
			return result;
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
				if (auto g = dyn_cast<GlobalValue>(v))
				{
					size_t globalIndex;
					if (auto var = dyn_cast<GlobalVariable>(g))
					{
						globalIndex = globals.accumulate(var);
					}
					else if (auto fn = dyn_cast<Function>(g))
					{
						globalIndex = globals.accumulate(fn);
					}
					else
					{
						assert(!"unknown type");
						throw invalid_argument("value");
					}
					string identifier;
					(raw_string_ostream(identifier) << "globals[" << globalIndex << "]").flush();
					set_name(v, identifier);
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
					(raw_string_ostream(argNumPrefix) << "val" << valueNames.size() << "_").flush();
					string identifier = dump_constant(os, types, argNumPrefix, c);
					set_name(v, identifier);
				}
				else
				{
					assert(!"not implemented");
					throw invalid_argument("value");
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
				// Do not emit a variable for block 0. This block can never be referenced anyways.
				// This allows the IRBuilder to pick up where the last generator function left.
				if (blockIndex != 0)
				{
					declare("BasicBlock", "block", blockIndex) << "llvm::BasicBlock::Create(context, \"\", function);" << nl;
				}
				blockIndices.insert(make_pair(&bb, blockIndex));
			}
			
			size_t count = 0;
			for (const Argument& arg : arguments)
			{
				string argName;
				raw_string_ostream ss(argName);
				ss << "arg" << count;
				ss.flush();
				set_name(arg, argName);
				count++;
			}
		}
		
		void visitBasicBlock(BasicBlock& bb)
		{
			// Assume that the first basic block is the one that the previous function left at.
			// LLVM functions cannot loop back to their first block, so it is safe to assume that this block
			// won't ever be referenced.
			auto iter = blockIndices.find(&bb);
			assert(iter != blockIndices.end());
			if (iter->second != 0)
			{
				os << nl << tab << "builder.SetInsertPoint(block" << iter->second << ");" << nl;
			}
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
			set_name(i, name);
		}
		
		void visitLoadInst(LoadInst& i)
		{
			string prefix = make_prefix("load");
			
			Value* pointer = i.getPointerOperand();
			ensure_exists(pointer, prefix);
			
			string varName = prefix + "var";
			declare(varName) << "builder.CreateLoad(" << name_of(pointer) << ", " << i.isVolatile() << ");" << nl;
			set_name(i, varName);
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
			set_name(i, varName);
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
			set_name(i, varName);
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
				declare("CallInst", varName) << "builder.CreateCall";
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
				
				declare("CallInst", varName) << "builder.CreateCall(" << name_of(called) << ", " << prefix << "array);" << nl;
			}
			
			for (const auto& pair : callInstAttributes)
			{
				if ((i.*pair.first)())
				{
					os << '\t' << varName << "->" << pair.second << "();" << nl;
				}
			}
			
			set_name(i, varName);
		}
		
		void visitUnreachableInst(UnreachableInst&)
		{
			os << '\t' << "builder.CreateUnreachable();" << nl;
		}
		
		void visitSwitchInst(SwitchInst& i)
		{
			string prefix = make_prefix("switch");
			
			BasicBlock* defaultCase = i.getDefaultDest();
			Value* condition = i.getCondition();
			ensure_exists(i.getCondition(), prefix);
			
			string varName = prefix + "var";
			declare("SwitchInst", varName) << "builder.CreateSwitch(" << name_of(condition) << ", " << name_of(defaultCase) << ", " << i.getNumCases() << ");" << nl;
			for (auto& switchCase : i.cases())
			{
				Value* caseValue = switchCase.getCaseValue();
				BasicBlock* caseBlock = switchCase.getCaseSuccessor();
				ensure_exists(caseValue, prefix);
				os << '\t' << varName << "->addCase(" << name_of(caseValue) << ", " << name_of(caseBlock) << ");" << nl;
			}
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
			else if (auto overflowing = dyn_cast<OverflowingBinaryOperator>(&i))
			{
				if (overflowing->hasNoSignedWrap())
				{
					os << "NSW";
				}
				else if (overflowing->hasNoUnsignedWrap())
				{
					os << "NUW";
				}
			}
			os << "(" << binaryOps[opcode] << ", " << name_of(left) << ", " << name_of(right) << ");" << nl;
			set_name(i, varName);
		}
		
		void visitCastInst(CastInst& i)
		{
			string prefix = make_prefix("cast");
			Value* casted = i.getOperand(0);
			ensure_exists(casted, prefix);
			
			size_t targetType = types.accumulate(i.getDestTy());
			string name = prefix + "var";
			declare(name) << "builder.CreateCast(" << castOps[i.getOpcode()] << ", " << name_of(casted) << ", types[" << targetType << "]);" << nl;
			set_name(i, name);
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
