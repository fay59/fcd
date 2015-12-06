//
// pass_removeundef.h
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

#ifndef fcd__ast_pass_removeundef_h
#define fcd__ast_pass_removeundef_h

#include "pass.h"
#include "pass_variablereferences.h"
#include "visitor.h"

class AstRemoveUndef : public AstFunctionPass, private StatementVisitor
{
	AstVariableReferencesPass& useAnalysisPass;
	Statement* toErase;
	FunctionNode* currentFunction;
	
	AstVariableReferences& useAnalysis() { return *useAnalysisPass.getReferences(*currentFunction); }
	virtual void visitAssignment(AssignmentNode* assignment) override;
	virtual void visitSequence(SequenceNode* sequence) override;
	virtual void visitLoop(LoopNode* loop) override;
	virtual void visitIfElse(IfElseNode* ifElse) override;
	
protected:
	virtual void doRun(FunctionNode& fn) override;
	
public:
	inline AstRemoveUndef(AstVariableReferencesPass& refs)
	: useAnalysisPass(refs)
	{
	}
	
	virtual const char* getName() const override;
};

#endif /* fcd__ast_pass_removeundef_h */
