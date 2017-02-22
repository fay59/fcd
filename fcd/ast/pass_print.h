//
// pass_print.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__ast_pass_print_h
#define fcd__ast_pass_print_h

#include "pass.h"

#include <llvm/Support/raw_ostream.h>

#include <string>
#include <vector>

class AstPrint final : public AstModulePass
{
	llvm::raw_ostream& output;
	std::vector<std::string> includes;
	
protected:
	virtual void doRun(std::deque<std::unique_ptr<FunctionNode>>& functions) override;
	
public:
	AstPrint(llvm::raw_ostream& output, std::vector<std::string> includes)
	: output(output), includes(std::move(includes))
	{
	}
	
	virtual const char* getName() const override;
};

#endif /* fcd__ast_pass_print_h */
