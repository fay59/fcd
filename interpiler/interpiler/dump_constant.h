//
//  constant_dumper.h
//  interpiler
//
//  Created by Félix on 2015-04-11.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __interpiler__constant_dumper__
#define __interpiler__constant_dumper__

#include <llvm/IR/Constant.h>
#include <llvm/Support/raw_ostream.h>
#include <string>

#include "type_dumper.h"
#include "synthesized_method.h"

std::string dump_constant(synthesized_method& into, type_dumper& types, const std::string& prefix, llvm::Constant* constant);

llvm::raw_ostream& operator<<(llvm::raw_ostream& into, bool b);

#endif /* defined(__interpiler__constant_dumper__) */
