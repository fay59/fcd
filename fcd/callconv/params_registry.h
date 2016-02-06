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

#ifndef fcd__callconv_params_registry_h
#define fcd__callconv_params_registry_h

#include "llvm_warnings.h"
#include "targetinfo.h"

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
#include <memory>
#include <string>
#include <unordered_map>

class CallingConvention;
class Executable;
class TargetInfo;
class TargetRegisterInfo;

struct ValueInformation
{
	// XXX: x86_64_systemv's call site analysis relies of IntegerRegister being first and Stack being last.
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
	// The stage of call information analysis is useful only when a recursive analysis
	// is going on.
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
	bool vararg;
	
public:
	CallInformation()
	: cc(nullptr), returnBegin(0), stage(New), vararg(false)
	{
	}
	
	CallInformation(const CallInformation& that) = default;
	CallInformation(CallInformation&& that) = default;
	
	CallInformation& operator=(const CallInformation& that) = default;
	CallInformation& operator=(CallInformation&& that) = default;
	
	llvm::AliasAnalysis::ModRefResult getRegisterModRef(const TargetRegisterInfo& reg) const;
	
	Stage getStage() const { return stage; }
	bool isVararg() const { return vararg; }
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
	
	size_t parameters_size() const
	{
		auto range = parameters();
		return range.end() - range.begin();
	}
	
	llvm::iterator_range<iterator> returns()
	{
		return llvm::make_range(return_begin(), values.end());
	}
	
	llvm::iterator_range<const_iterator> returns() const
	{
		return llvm::make_range(return_begin(), values.end());
	}
	
	size_t returns_size() const
	{
		auto range = returns();
		return range.end() - range.begin();
	}
	
	void clear() { values.clear(); }
	void setCallingConvention(CallingConvention* cc) { this->cc = cc; }
	void setStage(Stage stage) { this->stage = stage; }
	void setVararg(bool v = true) { this->vararg = v; }
	
	template<typename... T>
	void addParameter(T&&... params)
	{
		insertParameter(values.begin() + returnBegin, std::forward<T>(params)...);
	}
	
	template<typename... T>
	void insertParameter(iterator iter, T&&... params)
	{
		assert(iter <= values.begin() + returnBegin);
		values.emplace(iter, std::forward<T>(params)...);
		returnBegin++;
	}
	
	template<typename... T>
	void addReturn(T&&... params)
	{
		values.emplace_back(std::forward<T>(params)...);
	}
	
	template<typename... T>
	void insertReturn(iterator iter, T&&... params)
	{
		assert(iter >= values.begin() + returnBegin);
		values.emplace(iter, std::forward<T>(params)...);
	}
};

class ParameterRegistry : public llvm::ModulePass, public llvm::AliasAnalysis
{
	std::unique_ptr<TargetInfo> targetInfo;
	std::deque<CallingConvention*> ccChain;
	std::unordered_map<const llvm::Function*, CallInformation> callInformation;
	std::unordered_map<const llvm::Function*, std::unique_ptr<llvm::MemorySSA>> mssas;
	bool analyzing;
	
	void addCallingConvention(CallingConvention* cc)
	{
		assert(cc != nullptr);
		ccChain.push_back(cc);
	}
	
	CallInformation* analyzeFunction(llvm::Function& fn);
	void setupCCChain();
	
public:
	static char ID;
	
	typedef decltype(ccChain)::iterator iterator;
	typedef decltype(ccChain)::const_iterator const_iterator;
	
	ParameterRegistry()
	: llvm::ModulePass(ID)
	{
	}
	
	iterator begin() { return ccChain.begin(); }
	iterator end() { return ccChain.end(); }
	const_iterator begin() const { return ccChain.begin(); }
	const_iterator end() const { return ccChain.end(); }
	
	Executable* getExecutable();
	TargetInfo& getTargetInfo() { return *targetInfo; }
	
	const CallInformation* getCallInfo(llvm::Function& function);
	std::unique_ptr<CallInformation> analyzeCallSite(llvm::CallSite callSite);
	
	llvm::MemorySSA* getMemorySSA(llvm::Function& function);
	
	virtual void getAnalysisUsage(llvm::AnalysisUsage& au) const override;
	virtual const char* getPassName() const override;
	virtual bool doInitialization(llvm::Module& module) override;
	virtual bool runOnModule(llvm::Module& m) override;
	
	virtual void* getAdjustedAnalysisPointer(llvm::AnalysisID PI) override;
	virtual ModRefResult getModRefInfo(llvm::ImmutableCallSite cs, const llvm::MemoryLocation& location) override;
};

inline ParameterRegistry* createParameterRegistryPass()
{
	return new ParameterRegistry;
}

namespace llvm
{
	void initializeParameterRegistryPass(PassRegistry& PR);
}

#endif /* fcd__callconv_params_registry_h */
