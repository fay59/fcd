//
//  function_dumper.cpp
//  interpiler
//
//  Created by Félix on 2015-04-13.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <llvm/IR/InstVisitor.h>
#include <unordered_map>

#include "function_dumper.h"

using namespace llvm;
using namespace std;

namespace
{
	constexpr char nl = '\n';
	constexpr char tab = '\t';
	
	class to_string_visitor : public llvm::InstVisitor<to_string_visitor>
	{
		raw_ostream& os;
		unordered_map<const BasicBlock*, size_t> blockIndices;
		unordered_map<Value*, string> valueNames;
		
	public:
		to_string_visitor(raw_ostream& os, const iplist<BasicBlock>& blocks)
		: os(os)
		{
			for (const BasicBlock& bb : blocks)
			{
				size_t blockIndex = blockIndices.size();
				os << tab << "llvm::BasicBlock* block" << blockIndex << " = llvm::BasicBlock::Create(context, \"\", function);" << nl;
				blockIndices.insert(make_pair(&bb, blockIndex));
			}
		}
		
		void visitBasicBlock(BasicBlock& bb)
		{
			auto iter = blockIndices.find(&bb);
			assert(iter != blockIndices.end());
			os << tab << "builder.SetInsertPoint(block" << iter->second << ");" << nl;
		}
		
		void visitReturnInst(ReturnInst& i)
		{
			// This assumes just one ret per function. Otherwise it's gonna generate broken code, with a return statement
			// before the end of the function.
			os << tab << "return";
			if (Value* v = i.getReturnValue())
			{
				auto iter = valueNames.find(v);
				assert(iter != valueNames.end());
				os << " " << iter->second;
			}
			os << ';' << nl;
		}
	};
}



string function_dumper::make_function(llvm::Function *function, const std::string &prototype)
{
	string result;
	raw_string_ostream ss(result);
	
	ss << prototype << nl << '{' << nl;
	
	to_string_visitor visitor(ss, function->getBasicBlockList());
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
