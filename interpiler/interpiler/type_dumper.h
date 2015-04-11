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

#include "dumper.h"

class type_dumper : public dumper
{
	const dumped_item& make_dump(llvm::SequentialType* type, const std::string& typeName, uint64_t subclassData);
	const dumped_item& make_dump(llvm::Type* type, const std::string& typeMethod);
	const dumped_item& make_dump(llvm::IntegerType* type);
	const dumped_item& make_dump(llvm::FunctionType* type);
	const dumped_item& make_dump(llvm::ArrayType* type);
	const dumped_item& make_dump(llvm::PointerType* type);
	const dumped_item& make_dump(llvm::VectorType* type);
	const dumped_item& make_dump(llvm::StructType* type);
	const dumped_item& make_dump(llvm::Type* type);
	
public:
	using dumper::dumper;
	
	const dumped_item& dump(llvm::Type* type);
};

#endif /* defined(__interpiler__type_dumper__) */
