//
// statements.cpp
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

#include "statements.h"
#include "function.h"
#include "visitor.h"
#include "print.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/Support/raw_os_ostream.h>
SILENCE_LLVM_WARNINGS_END()

using namespace llvm;
using namespace std;

namespace
{
	KeywordStatement breakNode("break");
}

#pragma mark - Statements

void Statement::dump() const
{
	print(errs());
}

void Statement::printShort(raw_ostream& os) const
{
	StatementShortPrintVisitor print(os);
	const_cast<Statement&>(*this).visit(print);
}

void Statement::print(raw_ostream& os) const
{
	StatementPrintVisitor print(os);
	const_cast<Statement&>(*this).visit(print);
}

void SequenceStatement::visit(StatementVisitor &visitor)
{
	visitor.visitSequence(this);
}

void IfElseStatement::visit(StatementVisitor &visitor)
{
	visitor.visitIfElse(this);
}

LoopStatement::LoopStatement(Statement* body)
: LoopStatement(TokenExpression::trueExpression, PreTested, body)
{
}

void LoopStatement::visit(StatementVisitor &visitor)
{
	visitor.visitLoop(this);
}

KeywordStatement* KeywordStatement::breakNode = &::breakNode;

void KeywordStatement::visit(StatementVisitor &visitor)
{
	visitor.visitKeyword(this);
}

void ExpressionStatement::visit(StatementVisitor &visitor)
{
	visitor.visitExpression(this);
}

void DeclarationStatement::visit(StatementVisitor &visitor)
{
	visitor.visitDeclaration(this);
}

void AssignmentStatement::visit(StatementVisitor &visitor)
{
	visitor.visitAssignment(this);
}
