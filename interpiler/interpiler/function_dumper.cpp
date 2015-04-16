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

#define ENUM_STRING(x) [(size_t)x] = #x

namespace
{
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
	
#define LOOKUP_TABLE_ELEMENT(x, name, enum) [x] = "Instruction::" #name
	
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
	
	class to_method_visitor : public InstVisitor<to_method_visitor>
	{
		unique_ptr<raw_ostream> ostream;
		synthesized_method& method;
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
			(raw_string_ostream(result) << "block" << iter->second);
			return result;
		}
	
		string make_prefix(const string& name)
		{
			string prefix;
			raw_string_ostream prefixStream(prefix);
			(prefixStream << name << valueNames.size() << "_");
			return prefix;
		}
		
		raw_ostream& nl()
		{
			ostream.reset(new raw_string_ostream(method.nl()));
			return *ostream;
		}
		
		raw_ostream& declare(const string& type, const string& name, bool equals = true)
		{
			return nl() << type << " " << name << (equals ? " = " : " ");
		}
		
		raw_ostream& declare(const string& name)
		{
			return declare("Value*", name);
		}
		
		template<typename T>
		raw_ostream& declare(const string& type, const string& prefix, T&& append, bool equals = true)
		{
			return nl() << type << " " << prefix << append << (equals ? " = " : " ");
		}
		
		void ensure_exists(Value* v, const string& prefix)
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
					(raw_string_ostream(identifier) << "globals[" << globalIndex << "]");
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
					(raw_string_ostream(argNumPrefix) << "val" << valueNames.size() << "_");
					string identifier = dump_constant(method, types, argNumPrefix, c);
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
		to_method_visitor(synthesized_method& method, type_dumper& types, global_dumper& globals, const iplist<Argument>& arguments, const iplist<BasicBlock>& blocks)
		: method(method), types(types), globals(globals)
		{
			for (const BasicBlock& bb : blocks)
			{
				size_t blockIndex = blockIndices.size();
				// Do not emit a variable for block 0. This block can never be referenced anyways.
				// This allows the IRBuilder to pick up where the last generator function left.
				if (blockIndex != 0)
				{
					declare("BasicBlock", "block", blockIndex) << "BasicBlock::Create(context, \"\", function);";
				}
				blockIndices.insert(make_pair(&bb, blockIndex));
			}
			
			size_t count = 0;
			for (const Argument& arg : arguments)
			{
				string argName;
				(raw_string_ostream(argName) << "arg" << count);
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
				nl();
				nl() << "builder.SetInsertPoint(block" << iter->second << ");";
			}
		}
		
		void visitReturnInst(ReturnInst& i)
		{
			// This assumes just one ret per function. Otherwise it's gonna generate broken code, with a return statement
			// before the end of the function.
			auto& line = nl();
			line << "return";
			if (Value* v = i.getReturnValue())
			{
				line << " " << name_of(v);
			}
			line << ';';
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
			
			auto& arrayLine = declare("ArrayRef<Value*>", prefix, "array", false);
			arrayLine << "{ ";
			for (auto iter = i.idx_begin(); iter != i.idx_end(); iter++)
			{
				arrayLine << name_of(iter->get()) << ", ";
			}
			arrayLine << "};";
			
			string name = prefix + "var";
			auto& gepLine = declare(name);
			gepLine << "builder.Create";
			if (i.isInBounds())
			{
				gepLine << "InBounds";
			}
			gepLine << "GEP(" << valueNames[pointerOperand] << ", " << prefix << "array);";
			set_name(i, name);
		}
		
		void visitLoadInst(LoadInst& i)
		{
			string prefix = make_prefix("load");
			
			Value* pointer = i.getPointerOperand();
			ensure_exists(pointer, prefix);
			
			string varName = prefix + "var";
			declare(varName) << "builder.CreateLoad(" << name_of(pointer) << ", " << i.isVolatile() << ");";
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
			declare(varName) << "builder.CreateStore(" << name_of(value) << ", " << name_of(pointer) << ", " << i.isVolatile() << ");";
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
			auto& cmpLine = declare(varName);
			cmpLine << "builder.Create";
			if (i.isIntPredicate())
			{
				cmpLine << 'I';
			}
			else if (i.isFPPredicate())
			{
				cmpLine << 'F';
			}
			else
			{
				assert(!"not implemented");
			}
			
			CmpInst::Predicate pred = i.getPredicate();
			cmpLine << "Cmp(" << predicates[pred] << ", " << name_of(left) << ", " << name_of(right) << ");";
			set_name(i, varName);
		}
		
		void visitBranchInst(BranchInst& i)
		{
			string prefix = make_prefix("cmp");
			auto& line = nl();
			line << "builder.Create";
			if (i.isConditional())
			{
				auto value = i.getCondition();
				ensure_exists(value, prefix);
				line << "CondBr(" << name_of(value) << ", ";
				line << "block" << blockIndices[i.getSuccessor(0)] << ", ";
				line << "block" << blockIndices[i.getSuccessor(1)];
			}
			else
			{
				line << "Br(block" << blockIndices[i.getSuccessor(0)];
			}
			line << ");";
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
				auto& callLine = declare("CallInst", varName);
				callLine << "builder.CreateCall";
				if (numArgs > 1)
				{
					callLine << numArgs;
				}
				callLine << "(" << name_of(called);
				for (Use& use : i.arg_operands())
				{
					Value* arg = use.get();
					callLine << ", " << name_of(arg);
				}
				callLine << ");";
			}
			else
			{
				auto& arrayLine = nl();
				arrayLine << "Array<Value*> " << prefix << "array { ";
				for (Use& use : i.arg_operands())
				{
					Value* arg = use.get();
					arrayLine << name_of(arg) << ", ";
				}
				arrayLine << "};";
				
				declare("CallInst", varName) << "builder.CreateCall(" << name_of(called) << ", " << prefix << "array);";
			}
			
			for (const auto& pair : callInstAttributes)
			{
				if ((i.*pair.first)())
				{
					nl() << varName << "->" << pair.second << "();";
				}
			}
			
			set_name(i, varName);
		}
		
		void visitUnreachableInst(UnreachableInst&)
		{
			nl() << "builder.CreateUnreachable();";
		}
		
		void visitSwitchInst(SwitchInst& i)
		{
			string prefix = make_prefix("switch");
			
			BasicBlock* defaultCase = i.getDefaultDest();
			Value* condition = i.getCondition();
			ensure_exists(i.getCondition(), prefix);
			
			string varName = prefix + "var";
			auto& switchLine = declare("SwitchInst", varName);
			switchLine << "builder.CreateSwitch(" << name_of(condition) << ", " << name_of(defaultCase) << ", " << i.getNumCases() << ");";
			for (auto& switchCase : i.cases())
			{
				Value* caseValue = switchCase.getCaseValue();
				BasicBlock* caseBlock = switchCase.getCaseSuccessor();
				ensure_exists(caseValue, prefix);
				nl() << varName << "->addCase(" << name_of(caseValue) << ", " << name_of(caseBlock) << ");";
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
			auto& binopLine = declare(varName);
			binopLine << "BinaryOperator::Create";
			if (PossiblyExactOperator::isPossiblyExactOpcode(opcode) && i.isExact())
			{
				binopLine << "Exact";
			}
			else if (auto overflowing = dyn_cast<OverflowingBinaryOperator>(&i))
			{
				if (overflowing->hasNoSignedWrap())
				{
					binopLine << "NSW";
				}
				else if (overflowing->hasNoUnsignedWrap())
				{
					binopLine << "NUW";
				}
			}
			binopLine << "(" << binaryOps[opcode] << ", " << name_of(left) << ", " << name_of(right) << ");";
			set_name(i, varName);
		}
		
		void visitCastInst(CastInst& i)
		{
			string prefix = make_prefix("cast");
			Value* casted = i.getOperand(0);
			ensure_exists(casted, prefix);
			
			size_t targetType = types.accumulate(i.getDestTy());
			string name = prefix + "var";
			declare(name) << "builder.CreateCast(" << castOps[i.getOpcode()] << ", " << name_of(casted) << ", types[" << targetType << "]);";
			set_name(i, name);
		}
		
		// not implemented
		void visitInstruction(Instruction& i)
		{
			ostream.reset();
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

void function_dumper::make_function(Function *function, synthesized_method &method)
{
	method.nl() = "using namespace llvm;";
	to_method_visitor visitor(method, types, globals, function->getArgumentList(), function->getBasicBlockList());
	visitor.visit(function->begin(), function->end());
}

function_dumper::function_dumper(LLVMContext& ctx, synthesized_class& klass, type_dumper& types, global_dumper& globals)
: klass(klass), types(types), globals(globals), context(ctx)
{
	klass.new_field("llvm::IRBuilder<>", "builder", "context");
}

void function_dumper::accumulate(Function *function)
{
	if (function->isDeclaration() || known_functions.count(function) != 0)
	{
		return;
	}
	
	Type* returnType = function->getReturnType();
	string returnTypeAsString = returnType->isVoidTy() ? "void" : "llvm::Value*";
	
	synthesized_method& method = klass.new_method(returnTypeAsString, function->getName().str());
	
	const auto& argList = function->getArgumentList();
	for (size_t i = 0; i < argList.size(); i++)
	{
		string& param = method.new_param();
		(raw_string_ostream(param) << "llvm::Value* arg" << i);
	}
	
	known_functions.insert(function);
	make_function(function, method);
}
