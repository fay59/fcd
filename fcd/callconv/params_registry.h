//
// params_registry.h
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

#ifndef register_use_hpp
#define register_use_hpp

#include "llvm_warnings.h"
#include "pass_targetinfo.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/iterator_range.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/IR/Function.h>
#include <llvm/Pass.h>
#include "MemorySSA.h"
SILENCE_LLVM_WARNINGS_END()

#include <cassert>
#include <deque>
#include <string>
#include <unordered_map>

class CallingConvention;
class Executable;
class TargetInfo;
class TargetRegisterInfo;

struct ValueInformation
{
	enum StorageClass
	{
		IntegerRegister,
		FloatingPointRegister,
		Stack,
	};
	
	StorageClass type;
	union
	{
		const TargetRegisterInfo* registerInfo;
		uint64_t frameBaseOffset;
	};
	
	ValueInformation(StorageClass regType, uint64_t frameBaseOffset)
	: type(regType), frameBaseOffset(frameBaseOffset)
	{
		assert(type == Stack);
	}
	
	ValueInformation(StorageClass regType, const TargetRegisterInfo* registerInfo)
	: type(regType), registerInfo(registerInfo)
	{
		assert(type != Stack);
	}
};

class CallInformation
{
	typedef std::deque<ValueInformation> ContainerType;
	
public:
	enum Stage
	{
		New,
		Analyzing,
		Completed,
		Failed,
	};
	
	typedef ContainerType::iterator iterator;
	typedef ContainerType::const_iterator const_iterator;
	
private:
	CallingConvention* cc;
	ContainerType values;
	size_t returnBegin;
	Stage stage;
	
public:
	CallInformation()
	: cc(nullptr), stage(New)
	{
	}
	
	llvm::AliasAnalysis::ModRefResult getRegisterModRef(const TargetRegisterInfo& reg) const;
	
	Stage getStage() const { return stage; }
	CallingConvention* getCallingConvention() { return cc; }
	const CallingConvention* getCallingConvention() const { return cc; }
	
	iterator begin() { return values.begin(); }
	iterator end() { return values.end(); }
	const_iterator begin() const { return values.begin(); }
	const_iterator end() const { return values.end(); }
	
	iterator return_begin() { return values.begin() + returnBegin; }
	const_iterator return_begin() const { return values.begin() + returnBegin; }
	
	llvm::iterator_range<iterator> parameters()
	{
		return llvm::make_range(values.begin(), return_begin());
	}
	
	llvm::iterator_range<const_iterator> parameters() const
	{
		return llvm::make_range(values.begin(), return_begin());
	}
	
	llvm::iterator_range<iterator> returns()
	{
		return llvm::make_range(return_begin(), values.end());
	}
	
	llvm::iterator_range<const_iterator> returns() const
	{
		return llvm::make_range(return_begin(), values.end());
	}
	
	void clear() { values.clear(); }
	void setCallingConvention(CallingConvention* cc) { this->cc = cc; }
	void setStage(Stage stage) { this->stage = stage; }
	
	template<typename... T>
	void addParameter(T&&... params)
	{
		values.emplace(values.begin() + returnBegin, std::forward<T>(params)...);
		returnBegin++;
	}
	
	template<typename... T>
	void addReturn(T&&... params)
	{
		values.emplace_back(std::forward<T>(params)...);
	}
};

class ParameterRegistry : public llvm::ModulePass
{
	static char ID;
	
	std::deque<CallingConvention*> ccChain;
	Executable& executable;
	std::unordered_map<const llvm::Function*, CallInformation> callInformation;
	std::unordered_map<const llvm::Function*, std::unique_ptr<llvm::MemorySSA>> mssas;
	bool analyzing;
	
	CallInformation* analyzeFunction(llvm::Function& fn);
	
public:
	typedef decltype(ccChain)::iterator iterator;
	typedef decltype(ccChain)::const_iterator const_iterator;
	
	ParameterRegistry(Executable& executable)
	: llvm::ModulePass(ID), executable(executable)
	{
	}
	
	iterator begin() { return ccChain.begin(); }
	iterator end() { return ccChain.end(); }
	const_iterator begin() const { return ccChain.begin(); }
	const_iterator end() const { return ccChain.end(); }
	
	Executable& getExecutable() { return executable; }
	
	const CallInformation* getCallInfo(llvm::Function& function);
	
	llvm::MemorySSA* getMemorySSA(llvm::Function& function);
	
	virtual void getAnalysisUsage(llvm::AnalysisUsage& au) const override;
	virtual const char* getPassName() const override;
	virtual bool runOnModule(llvm::Module& m) override;
};

#endif /* register_use_hpp */
