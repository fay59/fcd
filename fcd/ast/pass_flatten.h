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

#ifndef fcd__ast_pass_flatten_h
#define fcd__ast_pass_flatten_h

#include "pass.h"
#include "visitor.h"

class AstFlatten final : public AstFunctionPass, private StatementVisitor
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
	
	void removeBranch(SequenceStatement& parent, size_t ifIndex, bool branch);
	void structurizeLoop(LoopStatement* loop);
	
	virtual void visitSequence(SequenceStatement* sequence) override;
	virtual void visitIfElse(IfElseStatement* ifElse) override;
	virtual void visitLoop(LoopStatement* loop) override;
	virtual void visitKeyword(KeywordStatement* keyword) override;
	virtual void visitExpression(ExpressionStatement* expression) override;
	virtual void visitDeclaration(DeclarationStatement* declaration) override;
	virtual void visitAssignment(AssignmentStatement* assignment) override;
	
protected:
	virtual void doRun(FunctionNode& fn) override;
	
public:
	virtual const char* getName() const override;
};

#endif /* fcd__ast_pass_flatten_h */
