//
// pass_flatten.h
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

#include "pass.h"
#include "visitor.h"

class AstFlatten : public AstFunctionPass, private StatementVisitor
{
	Statement* intermediate;
	
	template<typename T>
	inline Statement* flatten(T stmt)
	{
		if (stmt == nullptr)
		{
			return nullptr;
		}
		
		stmt->visit(*this);
		return intermediate;
	}
	
	void removeBranch(SequenceNode& parent, size_t ifIndex, bool branch);
	void structurizeLoop(LoopNode* loop);
	
	virtual void visitSequence(SequenceNode* sequence) override;
	virtual void visitIfElse(IfElseNode* ifElse) override;
	virtual void visitLoop(LoopNode* loop) override;
	virtual void visitKeyword(KeywordNode* keyword) override;
	virtual void visitExpression(ExpressionNode* expression) override;
	virtual void visitDeclaration(DeclarationNode* declaration) override;
	virtual void visitAssignment(AssignmentNode* assignment) override;
	
protected:
	virtual void doRun(FunctionNode& fn) override;
	
public:
	virtual const char* getName() const override;
};

#endif /* pass_flatten_cpp */
