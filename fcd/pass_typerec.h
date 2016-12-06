//
// pass_typerec.h
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

#ifndef pass_typerec_h
#define pass_typerec_h

#include <llvm/Pass.h>

#include <memory>
#include <unordered_set>

class TypeRecovery : public llvm::ModulePass
{
	static char ID;
	
	void analyzeFunction(llvm::Function& fn);
	
public:
	TypeRecovery();
	~TypeRecovery();
	
	virtual void getAnalysisUsage(llvm::AnalysisUsage& au) const override;
	virtual bool runOnModule(llvm::Module& module) override;
};

#endif /* pass_typerec_h */
