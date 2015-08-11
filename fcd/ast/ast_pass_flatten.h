//
// ast_pass_flatten.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is part of fcd.
//
// fcd is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// fcd is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with fcd.  If not, see <http://www.gnu.org/licenses/>.
//

#ifndef pass_flatten_cpp
#define pass_flatten_cpp

#include "ast_pass.h"

class AstFlatten : public AstPass
{
	Statement* flatten(Statement* base);
	Statement* flatten(IfElseNode* ifElse);
	Statement* flatten(LoopNode* loop);
	Statement* flatten(SequenceNode* sequence);
	Statement* flatten(AssignmentNode* assignment);
	
protected:
	virtual void doRun(FunctionNode& fn) override;
	
public:
	virtual const char* getName() const override;
};

#endif /* pass_flatten_cpp */
