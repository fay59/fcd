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
#include "visitor.h"

#include <unordered_map>

class AstRemoveUndef : public AstFunctionPass, private StatementVisitor, private ExpressionVisitor
{
	struct TokenInfo
	{
		llvm::SmallVector<AssignmentStatement*, 1> assignments;
		long useCount;
		
		TokenInfo()
		: useCount(0)
		{
		}
	};
	
	Statement* toErase;
	FunctionNode* currentFunction;
	std::unordered_map<TokenExpression*, TokenInfo> tokenInfo;
	
	virtual void visitAssignment(AssignmentStatement* assignment) override;
	virtual void visitSequence(SequenceStatement* sequence) override;
	virtual void visitLoop(LoopStatement* loop) override;
	virtual void visitIfElse(IfElseStatement* ifElse) override;
	
	virtual void visitToken(TokenExpression* token) override;
	
protected:
	virtual void doRun(FunctionNode& fn) override;
	
public:
	virtual const char* getName() const override;
	virtual ~AstRemoveUndef();
};

#endif /* fcd__ast_pass_removeundef_h */
