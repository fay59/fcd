//
//  type_dumper.h
//  interpiler
//
//  Created by Félix on 2015-04-11.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __interpiler__type_dumper__
#define __interpiler__type_dumper__

#include <llvm/IR/DerivedTypes.h>
#include <sstream>
#include <unordered_map>

#include "dumper.h"

class type_dumper
{
	std::stringstream method_body;
	std::unordered_map<llvm::Type*, size_t> type_indices;

	std::ostream& insert(llvm::Type* type);
	
	void make_dump(llvm::Type* type);
	void make_dump(llvm::SequentialType* type, const std::string& typeName, uint64_t subclassData);
	void make_dump(llvm::Type* type, const std::string& typeMethod);
	void make_dump(llvm::IntegerType* type);
	void make_dump(llvm::ArrayType* type);
	void make_dump(llvm::PointerType* type);
	void make_dump(llvm::VectorType* type);
	void make_dump(llvm::StructType* type);
	void make_dump(llvm::FunctionType* type);
	
public:
	type_dumper() = default;
	
	size_t accumulate(llvm::Type* type);
	std::string get_function_body(const std::string& functionName) const;
};

#endif /* defined(__interpiler__type_dumper__) */
