//
// params_registry.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__callconv_params_registry_h
#define fcd__callconv_params_registry_h

#include "targetinfo.h"
#include "pass_regaa.h"

#include <llvm/ADT/iterator_range.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/IR/Function.h>
#include <llvm/Pass.h>
#include <llvm/Transforms/Utils/MemorySSA.h>

#include <cassert>
#include <deque>
#include <memory>
#include <string>
#include <unordered_map>

class CallingConvention;
class Executable;
class TargetInfo;
struct TargetRegisterInfo;

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
	ptrdiff_t returnBegin;
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
	
	llvm::ModRefInfo getRegisterModRef(const TargetRegisterInfo& reg) const;
	
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
	
	iterator param_begin() { return begin(); }
	const_iterator param_begin() const { return begin(); }
	iterator param_end() { return return_begin(); }
	const_iterator param_end() const { return return_begin(); }
	
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
		return size_t(range.end() - range.begin());
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
		return size_t(range.end() - range.begin());
	}
	
	void clear() { values.clear(); }
	void setCallingConvention(CallingConvention* conv) { this->cc = conv; }
	void setStage(Stage s) { this->stage = s; }
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

class ParameterRegistryAAResults : public llvm::AAResultBase<ParameterRegistryAAResults>
{
	friend class llvm::AAResultBase<ParameterRegistryAAResults>;
	friend class ParameterRegistry;
	
	std::unordered_map<const llvm::Function*, CallInformation> callInformation;
	std::unique_ptr<TargetInfo> targetInfo;
	
public:
	ParameterRegistryAAResults(std::unique_ptr<TargetInfo> targetInfo)
	: targetInfo(move(targetInfo))
	{
	}
	
	ParameterRegistryAAResults(const ParameterRegistryAAResults&) = default;
	ParameterRegistryAAResults(ParameterRegistryAAResults&&) = default;
	
	bool invalidate(llvm::Function& fn, const llvm::PreservedAnalyses& pa)
	{
		// stateless
		// (either forever relevant or forever irrelevant for any function)
		return false;
	}
	
	llvm::ModRefInfo getModRefInfo(llvm::ImmutableCallSite cs, const llvm::MemoryLocation& loc);
	llvm::ModRefInfo getModRefInfo(llvm::ImmutableCallSite CS1, llvm::ImmutableCallSite CS2)
	{
		return AAResultBase::getModRefInfo(CS1, CS2);
	}
};

class ParameterRegistry final : public llvm::ModulePass
{
	std::unique_ptr<ParameterRegistryAAResults> aaResults;
	std::unique_ptr<TargetInfo> targetInfo;
	std::unique_ptr<ProgramMemoryAAResult> aaHack;
	std::deque<CallingConvention*> ccChain;
	std::unordered_map<const llvm::Function*, std::pair<unsigned, std::unique_ptr<llvm::MemorySSA>>> mssas;
	bool analyzing;
	
	void addCallingConvention(CallingConvention* cc)
	{
		assert(cc != nullptr);
		ccChain.push_back(cc);
	}
	
	CallInformation* analyzeFunction(llvm::Function& fn);
	void setupCCChain();
	
	std::unique_ptr<llvm::MemorySSA> createMemorySSA(llvm::Function& fn);
	
public:
	static char ID;
	
	typedef decltype(ccChain)::iterator iterator;
	typedef decltype(ccChain)::const_iterator const_iterator;
	
	ParameterRegistry();
	~ParameterRegistry();
	
	iterator begin() { return ccChain.begin(); }
	iterator end() { return ccChain.end(); }
	const_iterator begin() const { return ccChain.begin(); }
	const_iterator end() const { return ccChain.end(); }
	
	Executable* getExecutable();
	TargetInfo& getTargetInfo() { return *targetInfo; }
	
	ParameterRegistryAAResults& getAAResult() { return *aaResults; }
	const ParameterRegistryAAResults& getAAResult() const { return *aaResults; }
	
	const CallInformation* getCallInfo(llvm::Function& function);
	const CallInformation* getDefinitionCallInfo(llvm::Function& function);
	std::unique_ptr<CallInformation> analyzeCallSite(llvm::CallSite callSite);
	
	llvm::MemorySSA* getMemorySSA(llvm::Function& function);
	
	virtual void getAnalysisUsage(llvm::AnalysisUsage& au) const override;
	virtual const char* getPassName() const override;
	virtual bool doInitialization(llvm::Module& module) override;
	virtual bool runOnModule(llvm::Module& m) override;
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
