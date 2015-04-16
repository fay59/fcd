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
#include <llvm/Support/raw_ostream.h>
#include <memory>
#include <unordered_map>

#include "synthesized_class.h"
#include "synthesized_method.h"

class type_dumper
{
	synthesized_method& method;
	std::string& resizeLine;
	std::unordered_map<llvm::Type*, size_t> type_indices;

	std::unique_ptr<llvm::raw_ostream> ostream;
	llvm::raw_ostream& new_line();
	llvm::raw_ostream& insert(llvm::Type* type);
	
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
	static constexpr size_t npos = ~0;
	
	explicit type_dumper(synthesized_class& klass);
	
	size_t accumulate(llvm::Type* type);
	size_t index_of(llvm::Type* type) const;
};

#endif /* defined(__interpiler__type_dumper__) */
