//
//  value_dumper.h
//  interpiler
//
//  Created by Félix on 2015-04-11.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __interpiler__value_dumper__
#define __interpiler__value_dumper__

#include <llvm/IR/Value.h>

#include "dumper.h"

class value_dumper : public dumper
{
public:
	using dumper::dumper;
	
	const dumped_item& dump(llvm::Value* value);
};

#endif /* defined(__interpiler__value_dumper__) */
