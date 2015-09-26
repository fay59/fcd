#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"

#include "bindings.h"
#include <llvm-c/Core.h>
#include <memory>

static PyObject* Py_LLVMUse_GetNextUse(Py_LLVM_Wrapped<LLVMUseRef>* self);
static PyObject* Py_LLVMUse_GetUser(Py_LLVM_Wrapped<LLVMUseRef>* self);
static PyObject* Py_LLVMUse_GetUsedValue(Py_LLVM_Wrapped<LLVMUseRef>* self);

static PyMethodDef Py_LLVMUse_methods[] = {
	{"GetNextUse", (PyCFunction)&Py_LLVMUse_GetNextUse, METH_NOARGS, "Wrapper for LLVMGetNextUse"},
	{"GetUser", (PyCFunction)&Py_LLVMUse_GetUser, METH_NOARGS, "Wrapper for LLVMGetUser"},
	{"GetUsedValue", (PyCFunction)&Py_LLVMUse_GetUsedValue, METH_NOARGS, "Wrapper for LLVMGetUsedValue"},
	{nullptr}
};

PyTypeObject Py_LLVMUse_Type = {
	PyObject_HEAD_INIT(nullptr)
	.tp_name = "llvm.Use",
	.tp_basicsize = sizeof(Py_LLVM_Wrapped<LLVMUseRef>),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "Wrapper type for LLVMUseRef",
	.tp_methods = Py_LLVMUse_methods,
};

static PyObject* Py_LLVMModuleProvider_DisposeModuleProvider(Py_LLVM_Wrapped<LLVMModuleProviderRef>* self);
static PyObject* Py_LLVMModuleProvider_CreateFunctionPassManager(Py_LLVM_Wrapped<LLVMModuleProviderRef>* self);

static PyMethodDef Py_LLVMModuleProvider_methods[] = {
	{"DisposeModuleProvider", (PyCFunction)&Py_LLVMModuleProvider_DisposeModuleProvider, METH_NOARGS, "Wrapper for LLVMDisposeModuleProvider"},
	{"CreateFunctionPassManager", (PyCFunction)&Py_LLVMModuleProvider_CreateFunctionPassManager, METH_NOARGS, "Wrapper for LLVMCreateFunctionPassManager"},
	{nullptr}
};

PyTypeObject Py_LLVMModuleProvider_Type = {
	PyObject_HEAD_INIT(nullptr)
	.tp_name = "llvm.ModuleProvider",
	.tp_basicsize = sizeof(Py_LLVM_Wrapped<LLVMModuleProviderRef>),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "Wrapper type for LLVMModuleProviderRef",
	.tp_methods = Py_LLVMModuleProvider_methods,
};

static PyObject* Py_LLVMBuilder_PositionBuilder(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_PositionBuilderBefore(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_PositionBuilderAtEnd(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_GetInsertBlock(Py_LLVM_Wrapped<LLVMBuilderRef>* self);
static PyObject* Py_LLVMBuilder_ClearInsertionPosition(Py_LLVM_Wrapped<LLVMBuilderRef>* self);
static PyObject* Py_LLVMBuilder_InsertIntoBuilder(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_InsertIntoBuilderWithName(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_DisposeBuilder(Py_LLVM_Wrapped<LLVMBuilderRef>* self);
static PyObject* Py_LLVMBuilder_SetCurrentDebugLocation(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_GetCurrentDebugLocation(Py_LLVM_Wrapped<LLVMBuilderRef>* self);
static PyObject* Py_LLVMBuilder_SetInstDebugLocation(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildRetVoid(Py_LLVM_Wrapped<LLVMBuilderRef>* self);
static PyObject* Py_LLVMBuilder_BuildRet(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildBr(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildCondBr(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildSwitch(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildIndirectBr(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildInvoke(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildLandingPad(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildResume(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildUnreachable(Py_LLVM_Wrapped<LLVMBuilderRef>* self);
static PyObject* Py_LLVMBuilder_BuildAdd(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildNSWAdd(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildNUWAdd(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildFAdd(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildSub(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildNSWSub(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildNUWSub(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildFSub(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildMul(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildNSWMul(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildNUWMul(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildFMul(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildUDiv(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildSDiv(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildExactSDiv(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildFDiv(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildURem(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildSRem(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildFRem(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildShl(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildLShr(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildAShr(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildAnd(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildOr(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildXor(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildBinOp(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildNeg(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildNSWNeg(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildNUWNeg(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildFNeg(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildNot(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildMalloc(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildArrayMalloc(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildAlloca(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildArrayAlloca(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildFree(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildLoad(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildStore(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildGEP(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildInBoundsGEP(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildStructGEP(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildGlobalString(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildGlobalStringPtr(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildTrunc(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildZExt(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildSExt(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildFPToUI(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildFPToSI(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildUIToFP(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildSIToFP(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildFPTrunc(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildFPExt(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildPtrToInt(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildIntToPtr(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildBitCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildAddrSpaceCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildZExtOrBitCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildSExtOrBitCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildTruncOrBitCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildPointerCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildIntCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildFPCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildICmp(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildFCmp(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildPhi(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildCall(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildSelect(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildVAArg(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildExtractElement(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildInsertElement(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildShuffleVector(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildExtractValue(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildInsertValue(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildIsNull(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildIsNotNull(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildPtrDiff(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildFence(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);
static PyObject* Py_LLVMBuilder_BuildAtomicRMW(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args);

static PyMethodDef Py_LLVMBuilder_methods[] = {
	{"PositionBuilder", (PyCFunction)&Py_LLVMBuilder_PositionBuilder, METH_VARARGS, "Wrapper for LLVMPositionBuilder"},
	{"PositionBuilderBefore", (PyCFunction)&Py_LLVMBuilder_PositionBuilderBefore, METH_VARARGS, "Wrapper for LLVMPositionBuilderBefore"},
	{"PositionBuilderAtEnd", (PyCFunction)&Py_LLVMBuilder_PositionBuilderAtEnd, METH_VARARGS, "Wrapper for LLVMPositionBuilderAtEnd"},
	{"GetInsertBlock", (PyCFunction)&Py_LLVMBuilder_GetInsertBlock, METH_NOARGS, "Wrapper for LLVMGetInsertBlock"},
	{"ClearInsertionPosition", (PyCFunction)&Py_LLVMBuilder_ClearInsertionPosition, METH_NOARGS, "Wrapper for LLVMClearInsertionPosition"},
	{"InsertIntoBuilder", (PyCFunction)&Py_LLVMBuilder_InsertIntoBuilder, METH_VARARGS, "Wrapper for LLVMInsertIntoBuilder"},
	{"InsertIntoBuilderWithName", (PyCFunction)&Py_LLVMBuilder_InsertIntoBuilderWithName, METH_VARARGS, "Wrapper for LLVMInsertIntoBuilderWithName"},
	{"DisposeBuilder", (PyCFunction)&Py_LLVMBuilder_DisposeBuilder, METH_NOARGS, "Wrapper for LLVMDisposeBuilder"},
	{"SetCurrentDebugLocation", (PyCFunction)&Py_LLVMBuilder_SetCurrentDebugLocation, METH_VARARGS, "Wrapper for LLVMSetCurrentDebugLocation"},
	{"GetCurrentDebugLocation", (PyCFunction)&Py_LLVMBuilder_GetCurrentDebugLocation, METH_NOARGS, "Wrapper for LLVMGetCurrentDebugLocation"},
	{"SetInstDebugLocation", (PyCFunction)&Py_LLVMBuilder_SetInstDebugLocation, METH_VARARGS, "Wrapper for LLVMSetInstDebugLocation"},
	{"BuildRetVoid", (PyCFunction)&Py_LLVMBuilder_BuildRetVoid, METH_NOARGS, "Wrapper for LLVMBuildRetVoid"},
	{"BuildRet", (PyCFunction)&Py_LLVMBuilder_BuildRet, METH_VARARGS, "Wrapper for LLVMBuildRet"},
	{"BuildBr", (PyCFunction)&Py_LLVMBuilder_BuildBr, METH_VARARGS, "Wrapper for LLVMBuildBr"},
	{"BuildCondBr", (PyCFunction)&Py_LLVMBuilder_BuildCondBr, METH_VARARGS, "Wrapper for LLVMBuildCondBr"},
	{"BuildSwitch", (PyCFunction)&Py_LLVMBuilder_BuildSwitch, METH_VARARGS, "Wrapper for LLVMBuildSwitch"},
	{"BuildIndirectBr", (PyCFunction)&Py_LLVMBuilder_BuildIndirectBr, METH_VARARGS, "Wrapper for LLVMBuildIndirectBr"},
	{"BuildInvoke", (PyCFunction)&Py_LLVMBuilder_BuildInvoke, METH_VARARGS, "Wrapper for LLVMBuildInvoke"},
	{"BuildLandingPad", (PyCFunction)&Py_LLVMBuilder_BuildLandingPad, METH_VARARGS, "Wrapper for LLVMBuildLandingPad"},
	{"BuildResume", (PyCFunction)&Py_LLVMBuilder_BuildResume, METH_VARARGS, "Wrapper for LLVMBuildResume"},
	{"BuildUnreachable", (PyCFunction)&Py_LLVMBuilder_BuildUnreachable, METH_NOARGS, "Wrapper for LLVMBuildUnreachable"},
	{"BuildAdd", (PyCFunction)&Py_LLVMBuilder_BuildAdd, METH_VARARGS, "Wrapper for LLVMBuildAdd"},
	{"BuildNSWAdd", (PyCFunction)&Py_LLVMBuilder_BuildNSWAdd, METH_VARARGS, "Wrapper for LLVMBuildNSWAdd"},
	{"BuildNUWAdd", (PyCFunction)&Py_LLVMBuilder_BuildNUWAdd, METH_VARARGS, "Wrapper for LLVMBuildNUWAdd"},
	{"BuildFAdd", (PyCFunction)&Py_LLVMBuilder_BuildFAdd, METH_VARARGS, "Wrapper for LLVMBuildFAdd"},
	{"BuildSub", (PyCFunction)&Py_LLVMBuilder_BuildSub, METH_VARARGS, "Wrapper for LLVMBuildSub"},
	{"BuildNSWSub", (PyCFunction)&Py_LLVMBuilder_BuildNSWSub, METH_VARARGS, "Wrapper for LLVMBuildNSWSub"},
	{"BuildNUWSub", (PyCFunction)&Py_LLVMBuilder_BuildNUWSub, METH_VARARGS, "Wrapper for LLVMBuildNUWSub"},
	{"BuildFSub", (PyCFunction)&Py_LLVMBuilder_BuildFSub, METH_VARARGS, "Wrapper for LLVMBuildFSub"},
	{"BuildMul", (PyCFunction)&Py_LLVMBuilder_BuildMul, METH_VARARGS, "Wrapper for LLVMBuildMul"},
	{"BuildNSWMul", (PyCFunction)&Py_LLVMBuilder_BuildNSWMul, METH_VARARGS, "Wrapper for LLVMBuildNSWMul"},
	{"BuildNUWMul", (PyCFunction)&Py_LLVMBuilder_BuildNUWMul, METH_VARARGS, "Wrapper for LLVMBuildNUWMul"},
	{"BuildFMul", (PyCFunction)&Py_LLVMBuilder_BuildFMul, METH_VARARGS, "Wrapper for LLVMBuildFMul"},
	{"BuildUDiv", (PyCFunction)&Py_LLVMBuilder_BuildUDiv, METH_VARARGS, "Wrapper for LLVMBuildUDiv"},
	{"BuildSDiv", (PyCFunction)&Py_LLVMBuilder_BuildSDiv, METH_VARARGS, "Wrapper for LLVMBuildSDiv"},
	{"BuildExactSDiv", (PyCFunction)&Py_LLVMBuilder_BuildExactSDiv, METH_VARARGS, "Wrapper for LLVMBuildExactSDiv"},
	{"BuildFDiv", (PyCFunction)&Py_LLVMBuilder_BuildFDiv, METH_VARARGS, "Wrapper for LLVMBuildFDiv"},
	{"BuildURem", (PyCFunction)&Py_LLVMBuilder_BuildURem, METH_VARARGS, "Wrapper for LLVMBuildURem"},
	{"BuildSRem", (PyCFunction)&Py_LLVMBuilder_BuildSRem, METH_VARARGS, "Wrapper for LLVMBuildSRem"},
	{"BuildFRem", (PyCFunction)&Py_LLVMBuilder_BuildFRem, METH_VARARGS, "Wrapper for LLVMBuildFRem"},
	{"BuildShl", (PyCFunction)&Py_LLVMBuilder_BuildShl, METH_VARARGS, "Wrapper for LLVMBuildShl"},
	{"BuildLShr", (PyCFunction)&Py_LLVMBuilder_BuildLShr, METH_VARARGS, "Wrapper for LLVMBuildLShr"},
	{"BuildAShr", (PyCFunction)&Py_LLVMBuilder_BuildAShr, METH_VARARGS, "Wrapper for LLVMBuildAShr"},
	{"BuildAnd", (PyCFunction)&Py_LLVMBuilder_BuildAnd, METH_VARARGS, "Wrapper for LLVMBuildAnd"},
	{"BuildOr", (PyCFunction)&Py_LLVMBuilder_BuildOr, METH_VARARGS, "Wrapper for LLVMBuildOr"},
	{"BuildXor", (PyCFunction)&Py_LLVMBuilder_BuildXor, METH_VARARGS, "Wrapper for LLVMBuildXor"},
	{"BuildBinOp", (PyCFunction)&Py_LLVMBuilder_BuildBinOp, METH_VARARGS, "Wrapper for LLVMBuildBinOp"},
	{"BuildNeg", (PyCFunction)&Py_LLVMBuilder_BuildNeg, METH_VARARGS, "Wrapper for LLVMBuildNeg"},
	{"BuildNSWNeg", (PyCFunction)&Py_LLVMBuilder_BuildNSWNeg, METH_VARARGS, "Wrapper for LLVMBuildNSWNeg"},
	{"BuildNUWNeg", (PyCFunction)&Py_LLVMBuilder_BuildNUWNeg, METH_VARARGS, "Wrapper for LLVMBuildNUWNeg"},
	{"BuildFNeg", (PyCFunction)&Py_LLVMBuilder_BuildFNeg, METH_VARARGS, "Wrapper for LLVMBuildFNeg"},
	{"BuildNot", (PyCFunction)&Py_LLVMBuilder_BuildNot, METH_VARARGS, "Wrapper for LLVMBuildNot"},
	{"BuildMalloc", (PyCFunction)&Py_LLVMBuilder_BuildMalloc, METH_VARARGS, "Wrapper for LLVMBuildMalloc"},
	{"BuildArrayMalloc", (PyCFunction)&Py_LLVMBuilder_BuildArrayMalloc, METH_VARARGS, "Wrapper for LLVMBuildArrayMalloc"},
	{"BuildAlloca", (PyCFunction)&Py_LLVMBuilder_BuildAlloca, METH_VARARGS, "Wrapper for LLVMBuildAlloca"},
	{"BuildArrayAlloca", (PyCFunction)&Py_LLVMBuilder_BuildArrayAlloca, METH_VARARGS, "Wrapper for LLVMBuildArrayAlloca"},
	{"BuildFree", (PyCFunction)&Py_LLVMBuilder_BuildFree, METH_VARARGS, "Wrapper for LLVMBuildFree"},
	{"BuildLoad", (PyCFunction)&Py_LLVMBuilder_BuildLoad, METH_VARARGS, "Wrapper for LLVMBuildLoad"},
	{"BuildStore", (PyCFunction)&Py_LLVMBuilder_BuildStore, METH_VARARGS, "Wrapper for LLVMBuildStore"},
	{"BuildGEP", (PyCFunction)&Py_LLVMBuilder_BuildGEP, METH_VARARGS, "Wrapper for LLVMBuildGEP"},
	{"BuildInBoundsGEP", (PyCFunction)&Py_LLVMBuilder_BuildInBoundsGEP, METH_VARARGS, "Wrapper for LLVMBuildInBoundsGEP"},
	{"BuildStructGEP", (PyCFunction)&Py_LLVMBuilder_BuildStructGEP, METH_VARARGS, "Wrapper for LLVMBuildStructGEP"},
	{"BuildGlobalString", (PyCFunction)&Py_LLVMBuilder_BuildGlobalString, METH_VARARGS, "Wrapper for LLVMBuildGlobalString"},
	{"BuildGlobalStringPtr", (PyCFunction)&Py_LLVMBuilder_BuildGlobalStringPtr, METH_VARARGS, "Wrapper for LLVMBuildGlobalStringPtr"},
	{"BuildTrunc", (PyCFunction)&Py_LLVMBuilder_BuildTrunc, METH_VARARGS, "Wrapper for LLVMBuildTrunc"},
	{"BuildZExt", (PyCFunction)&Py_LLVMBuilder_BuildZExt, METH_VARARGS, "Wrapper for LLVMBuildZExt"},
	{"BuildSExt", (PyCFunction)&Py_LLVMBuilder_BuildSExt, METH_VARARGS, "Wrapper for LLVMBuildSExt"},
	{"BuildFPToUI", (PyCFunction)&Py_LLVMBuilder_BuildFPToUI, METH_VARARGS, "Wrapper for LLVMBuildFPToUI"},
	{"BuildFPToSI", (PyCFunction)&Py_LLVMBuilder_BuildFPToSI, METH_VARARGS, "Wrapper for LLVMBuildFPToSI"},
	{"BuildUIToFP", (PyCFunction)&Py_LLVMBuilder_BuildUIToFP, METH_VARARGS, "Wrapper for LLVMBuildUIToFP"},
	{"BuildSIToFP", (PyCFunction)&Py_LLVMBuilder_BuildSIToFP, METH_VARARGS, "Wrapper for LLVMBuildSIToFP"},
	{"BuildFPTrunc", (PyCFunction)&Py_LLVMBuilder_BuildFPTrunc, METH_VARARGS, "Wrapper for LLVMBuildFPTrunc"},
	{"BuildFPExt", (PyCFunction)&Py_LLVMBuilder_BuildFPExt, METH_VARARGS, "Wrapper for LLVMBuildFPExt"},
	{"BuildPtrToInt", (PyCFunction)&Py_LLVMBuilder_BuildPtrToInt, METH_VARARGS, "Wrapper for LLVMBuildPtrToInt"},
	{"BuildIntToPtr", (PyCFunction)&Py_LLVMBuilder_BuildIntToPtr, METH_VARARGS, "Wrapper for LLVMBuildIntToPtr"},
	{"BuildBitCast", (PyCFunction)&Py_LLVMBuilder_BuildBitCast, METH_VARARGS, "Wrapper for LLVMBuildBitCast"},
	{"BuildAddrSpaceCast", (PyCFunction)&Py_LLVMBuilder_BuildAddrSpaceCast, METH_VARARGS, "Wrapper for LLVMBuildAddrSpaceCast"},
	{"BuildZExtOrBitCast", (PyCFunction)&Py_LLVMBuilder_BuildZExtOrBitCast, METH_VARARGS, "Wrapper for LLVMBuildZExtOrBitCast"},
	{"BuildSExtOrBitCast", (PyCFunction)&Py_LLVMBuilder_BuildSExtOrBitCast, METH_VARARGS, "Wrapper for LLVMBuildSExtOrBitCast"},
	{"BuildTruncOrBitCast", (PyCFunction)&Py_LLVMBuilder_BuildTruncOrBitCast, METH_VARARGS, "Wrapper for LLVMBuildTruncOrBitCast"},
	{"BuildCast", (PyCFunction)&Py_LLVMBuilder_BuildCast, METH_VARARGS, "Wrapper for LLVMBuildCast"},
	{"BuildPointerCast", (PyCFunction)&Py_LLVMBuilder_BuildPointerCast, METH_VARARGS, "Wrapper for LLVMBuildPointerCast"},
	{"BuildIntCast", (PyCFunction)&Py_LLVMBuilder_BuildIntCast, METH_VARARGS, "Wrapper for LLVMBuildIntCast"},
	{"BuildFPCast", (PyCFunction)&Py_LLVMBuilder_BuildFPCast, METH_VARARGS, "Wrapper for LLVMBuildFPCast"},
	{"BuildICmp", (PyCFunction)&Py_LLVMBuilder_BuildICmp, METH_VARARGS, "Wrapper for LLVMBuildICmp"},
	{"BuildFCmp", (PyCFunction)&Py_LLVMBuilder_BuildFCmp, METH_VARARGS, "Wrapper for LLVMBuildFCmp"},
	{"BuildPhi", (PyCFunction)&Py_LLVMBuilder_BuildPhi, METH_VARARGS, "Wrapper for LLVMBuildPhi"},
	{"BuildCall", (PyCFunction)&Py_LLVMBuilder_BuildCall, METH_VARARGS, "Wrapper for LLVMBuildCall"},
	{"BuildSelect", (PyCFunction)&Py_LLVMBuilder_BuildSelect, METH_VARARGS, "Wrapper for LLVMBuildSelect"},
	{"BuildVAArg", (PyCFunction)&Py_LLVMBuilder_BuildVAArg, METH_VARARGS, "Wrapper for LLVMBuildVAArg"},
	{"BuildExtractElement", (PyCFunction)&Py_LLVMBuilder_BuildExtractElement, METH_VARARGS, "Wrapper for LLVMBuildExtractElement"},
	{"BuildInsertElement", (PyCFunction)&Py_LLVMBuilder_BuildInsertElement, METH_VARARGS, "Wrapper for LLVMBuildInsertElement"},
	{"BuildShuffleVector", (PyCFunction)&Py_LLVMBuilder_BuildShuffleVector, METH_VARARGS, "Wrapper for LLVMBuildShuffleVector"},
	{"BuildExtractValue", (PyCFunction)&Py_LLVMBuilder_BuildExtractValue, METH_VARARGS, "Wrapper for LLVMBuildExtractValue"},
	{"BuildInsertValue", (PyCFunction)&Py_LLVMBuilder_BuildInsertValue, METH_VARARGS, "Wrapper for LLVMBuildInsertValue"},
	{"BuildIsNull", (PyCFunction)&Py_LLVMBuilder_BuildIsNull, METH_VARARGS, "Wrapper for LLVMBuildIsNull"},
	{"BuildIsNotNull", (PyCFunction)&Py_LLVMBuilder_BuildIsNotNull, METH_VARARGS, "Wrapper for LLVMBuildIsNotNull"},
	{"BuildPtrDiff", (PyCFunction)&Py_LLVMBuilder_BuildPtrDiff, METH_VARARGS, "Wrapper for LLVMBuildPtrDiff"},
	{"BuildFence", (PyCFunction)&Py_LLVMBuilder_BuildFence, METH_VARARGS, "Wrapper for LLVMBuildFence"},
	{"BuildAtomicRMW", (PyCFunction)&Py_LLVMBuilder_BuildAtomicRMW, METH_VARARGS, "Wrapper for LLVMBuildAtomicRMW"},
	{nullptr}
};

PyTypeObject Py_LLVMBuilder_Type = {
	PyObject_HEAD_INIT(nullptr)
	.tp_name = "llvm.Builder",
	.tp_basicsize = sizeof(Py_LLVM_Wrapped<LLVMBuilderRef>),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "Wrapper type for LLVMBuilderRef",
	.tp_methods = Py_LLVMBuilder_methods,
};

static PyObject* Py_LLVMValue_GetNextFunction(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetPreviousFunction(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_TypeOf(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetValueName(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetValueName(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_DumpValue(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_ReplaceAllUsesWith(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_IsConstant(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_IsUndef(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_IsAArgument(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_IsAMDNode(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_IsAMDString(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetFirstUse(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetOperand(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetOperandUse(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_SetOperand(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_IsNull(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_IsConstantString(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetElementAsConstant(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetConstOpcode(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_BlockAddress(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetGlobalParent(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_IsDeclaration(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetLinkage(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetLinkage(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetSection(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetSection(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetVisibility(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetVisibility(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetDLLStorageClass(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetDLLStorageClass(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_HasUnnamedAddr(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetUnnamedAddr(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetAlignment(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetAlignment(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetNextGlobal(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetPreviousGlobal(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_DeleteGlobal(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetInitializer(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetInitializer(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_IsThreadLocal(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetThreadLocal(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_IsGlobalConstant(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetGlobalConstant(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetThreadLocalMode(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetThreadLocalMode(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_IsExternallyInitialized(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetExternallyInitialized(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_DeleteFunction(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetPersonalityFn(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetPersonalityFn(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetIntrinsicID(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetFunctionCallConv(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetFunctionCallConv(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetGC(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetGC(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_AddFunctionAttr(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_AddTargetDependentFunctionAttr(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetFunctionAttr(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_RemoveFunctionAttr(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_CountParams(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetParam(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetParamParent(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetFirstParam(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetLastParam(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetNextParam(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetPreviousParam(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_AddAttribute(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_RemoveAttribute(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetAttribute(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetParamAlignment(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetMDNodeNumOperands(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_ValueIsBasicBlock(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_ValueAsBasicBlock(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_CountBasicBlocks(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetFirstBasicBlock(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetLastBasicBlock(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetEntryBasicBlock(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_AppendBasicBlock(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetMetadata(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_SetMetadata(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetInstructionParent(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetNextInstruction(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetPreviousInstruction(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_InstructionEraseFromParent(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetInstructionOpcode(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetICmpPredicate(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetFCmpPredicate(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_InstructionClone(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetInstructionCallConv(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetInstructionCallConv(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_AddInstrAttribute(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_RemoveInstrAttribute(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_SetInstrParamAlignment(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_IsTailCall(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetTailCall(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetNumSuccessors(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetSuccessor(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_SetSuccessor(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_IsConditional(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetCondition(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetCondition(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetSwitchDefaultDest(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_CountIncoming(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_GetIncomingValue(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetIncomingBlock(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_AddCase(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_AddDestination(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_AddClause(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_SetCleanup(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);
static PyObject* Py_LLVMValue_GetVolatile(Py_LLVM_Wrapped<LLVMValueRef>* self);
static PyObject* Py_LLVMValue_SetVolatile(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args);

static PyMethodDef Py_LLVMValue_methods[] = {
	{"GetNextFunction", (PyCFunction)&Py_LLVMValue_GetNextFunction, METH_NOARGS, "Wrapper for LLVMGetNextFunction"},
	{"GetPreviousFunction", (PyCFunction)&Py_LLVMValue_GetPreviousFunction, METH_NOARGS, "Wrapper for LLVMGetPreviousFunction"},
	{"TypeOf", (PyCFunction)&Py_LLVMValue_TypeOf, METH_NOARGS, "Wrapper for LLVMTypeOf"},
	{"GetValueName", (PyCFunction)&Py_LLVMValue_GetValueName, METH_NOARGS, "Wrapper for LLVMGetValueName"},
	{"SetValueName", (PyCFunction)&Py_LLVMValue_SetValueName, METH_VARARGS, "Wrapper for LLVMSetValueName"},
	{"DumpValue", (PyCFunction)&Py_LLVMValue_DumpValue, METH_NOARGS, "Wrapper for LLVMDumpValue"},
	{"ReplaceAllUsesWith", (PyCFunction)&Py_LLVMValue_ReplaceAllUsesWith, METH_VARARGS, "Wrapper for LLVMReplaceAllUsesWith"},
	{"IsConstant", (PyCFunction)&Py_LLVMValue_IsConstant, METH_NOARGS, "Wrapper for LLVMIsConstant"},
	{"IsUndef", (PyCFunction)&Py_LLVMValue_IsUndef, METH_NOARGS, "Wrapper for LLVMIsUndef"},
	{"IsAArgument", (PyCFunction)&Py_LLVMValue_IsAArgument, METH_NOARGS, "Wrapper for LLVMIsAArgument"},
	{"IsAMDNode", (PyCFunction)&Py_LLVMValue_IsAMDNode, METH_NOARGS, "Wrapper for LLVMIsAMDNode"},
	{"IsAMDString", (PyCFunction)&Py_LLVMValue_IsAMDString, METH_NOARGS, "Wrapper for LLVMIsAMDString"},
	{"GetFirstUse", (PyCFunction)&Py_LLVMValue_GetFirstUse, METH_NOARGS, "Wrapper for LLVMGetFirstUse"},
	{"GetOperand", (PyCFunction)&Py_LLVMValue_GetOperand, METH_VARARGS, "Wrapper for LLVMGetOperand"},
	{"GetOperandUse", (PyCFunction)&Py_LLVMValue_GetOperandUse, METH_VARARGS, "Wrapper for LLVMGetOperandUse"},
	{"SetOperand", (PyCFunction)&Py_LLVMValue_SetOperand, METH_VARARGS, "Wrapper for LLVMSetOperand"},
	{"IsNull", (PyCFunction)&Py_LLVMValue_IsNull, METH_NOARGS, "Wrapper for LLVMIsNull"},
	{"IsConstantString", (PyCFunction)&Py_LLVMValue_IsConstantString, METH_NOARGS, "Wrapper for LLVMIsConstantString"},
	{"GetElementAsConstant", (PyCFunction)&Py_LLVMValue_GetElementAsConstant, METH_VARARGS, "Wrapper for LLVMGetElementAsConstant"},
	{"GetConstOpcode", (PyCFunction)&Py_LLVMValue_GetConstOpcode, METH_NOARGS, "Wrapper for LLVMGetConstOpcode"},
	{"BlockAddress", (PyCFunction)&Py_LLVMValue_BlockAddress, METH_VARARGS, "Wrapper for LLVMBlockAddress"},
	{"GetGlobalParent", (PyCFunction)&Py_LLVMValue_GetGlobalParent, METH_NOARGS, "Wrapper for LLVMGetGlobalParent"},
	{"IsDeclaration", (PyCFunction)&Py_LLVMValue_IsDeclaration, METH_NOARGS, "Wrapper for LLVMIsDeclaration"},
	{"GetLinkage", (PyCFunction)&Py_LLVMValue_GetLinkage, METH_NOARGS, "Wrapper for LLVMGetLinkage"},
	{"SetLinkage", (PyCFunction)&Py_LLVMValue_SetLinkage, METH_VARARGS, "Wrapper for LLVMSetLinkage"},
	{"GetSection", (PyCFunction)&Py_LLVMValue_GetSection, METH_NOARGS, "Wrapper for LLVMGetSection"},
	{"SetSection", (PyCFunction)&Py_LLVMValue_SetSection, METH_VARARGS, "Wrapper for LLVMSetSection"},
	{"GetVisibility", (PyCFunction)&Py_LLVMValue_GetVisibility, METH_NOARGS, "Wrapper for LLVMGetVisibility"},
	{"SetVisibility", (PyCFunction)&Py_LLVMValue_SetVisibility, METH_VARARGS, "Wrapper for LLVMSetVisibility"},
	{"GetDLLStorageClass", (PyCFunction)&Py_LLVMValue_GetDLLStorageClass, METH_NOARGS, "Wrapper for LLVMGetDLLStorageClass"},
	{"SetDLLStorageClass", (PyCFunction)&Py_LLVMValue_SetDLLStorageClass, METH_VARARGS, "Wrapper for LLVMSetDLLStorageClass"},
	{"HasUnnamedAddr", (PyCFunction)&Py_LLVMValue_HasUnnamedAddr, METH_NOARGS, "Wrapper for LLVMHasUnnamedAddr"},
	{"SetUnnamedAddr", (PyCFunction)&Py_LLVMValue_SetUnnamedAddr, METH_VARARGS, "Wrapper for LLVMSetUnnamedAddr"},
	{"GetAlignment", (PyCFunction)&Py_LLVMValue_GetAlignment, METH_NOARGS, "Wrapper for LLVMGetAlignment"},
	{"SetAlignment", (PyCFunction)&Py_LLVMValue_SetAlignment, METH_VARARGS, "Wrapper for LLVMSetAlignment"},
	{"GetNextGlobal", (PyCFunction)&Py_LLVMValue_GetNextGlobal, METH_NOARGS, "Wrapper for LLVMGetNextGlobal"},
	{"GetPreviousGlobal", (PyCFunction)&Py_LLVMValue_GetPreviousGlobal, METH_NOARGS, "Wrapper for LLVMGetPreviousGlobal"},
	{"DeleteGlobal", (PyCFunction)&Py_LLVMValue_DeleteGlobal, METH_NOARGS, "Wrapper for LLVMDeleteGlobal"},
	{"GetInitializer", (PyCFunction)&Py_LLVMValue_GetInitializer, METH_NOARGS, "Wrapper for LLVMGetInitializer"},
	{"SetInitializer", (PyCFunction)&Py_LLVMValue_SetInitializer, METH_VARARGS, "Wrapper for LLVMSetInitializer"},
	{"IsThreadLocal", (PyCFunction)&Py_LLVMValue_IsThreadLocal, METH_NOARGS, "Wrapper for LLVMIsThreadLocal"},
	{"SetThreadLocal", (PyCFunction)&Py_LLVMValue_SetThreadLocal, METH_VARARGS, "Wrapper for LLVMSetThreadLocal"},
	{"IsGlobalConstant", (PyCFunction)&Py_LLVMValue_IsGlobalConstant, METH_NOARGS, "Wrapper for LLVMIsGlobalConstant"},
	{"SetGlobalConstant", (PyCFunction)&Py_LLVMValue_SetGlobalConstant, METH_VARARGS, "Wrapper for LLVMSetGlobalConstant"},
	{"GetThreadLocalMode", (PyCFunction)&Py_LLVMValue_GetThreadLocalMode, METH_NOARGS, "Wrapper for LLVMGetThreadLocalMode"},
	{"SetThreadLocalMode", (PyCFunction)&Py_LLVMValue_SetThreadLocalMode, METH_VARARGS, "Wrapper for LLVMSetThreadLocalMode"},
	{"IsExternallyInitialized", (PyCFunction)&Py_LLVMValue_IsExternallyInitialized, METH_NOARGS, "Wrapper for LLVMIsExternallyInitialized"},
	{"SetExternallyInitialized", (PyCFunction)&Py_LLVMValue_SetExternallyInitialized, METH_VARARGS, "Wrapper for LLVMSetExternallyInitialized"},
	{"DeleteFunction", (PyCFunction)&Py_LLVMValue_DeleteFunction, METH_NOARGS, "Wrapper for LLVMDeleteFunction"},
	{"GetPersonalityFn", (PyCFunction)&Py_LLVMValue_GetPersonalityFn, METH_NOARGS, "Wrapper for LLVMGetPersonalityFn"},
	{"SetPersonalityFn", (PyCFunction)&Py_LLVMValue_SetPersonalityFn, METH_VARARGS, "Wrapper for LLVMSetPersonalityFn"},
	{"GetIntrinsicID", (PyCFunction)&Py_LLVMValue_GetIntrinsicID, METH_NOARGS, "Wrapper for LLVMGetIntrinsicID"},
	{"GetFunctionCallConv", (PyCFunction)&Py_LLVMValue_GetFunctionCallConv, METH_NOARGS, "Wrapper for LLVMGetFunctionCallConv"},
	{"SetFunctionCallConv", (PyCFunction)&Py_LLVMValue_SetFunctionCallConv, METH_VARARGS, "Wrapper for LLVMSetFunctionCallConv"},
	{"GetGC", (PyCFunction)&Py_LLVMValue_GetGC, METH_NOARGS, "Wrapper for LLVMGetGC"},
	{"SetGC", (PyCFunction)&Py_LLVMValue_SetGC, METH_VARARGS, "Wrapper for LLVMSetGC"},
	{"AddFunctionAttr", (PyCFunction)&Py_LLVMValue_AddFunctionAttr, METH_VARARGS, "Wrapper for LLVMAddFunctionAttr"},
	{"AddTargetDependentFunctionAttr", (PyCFunction)&Py_LLVMValue_AddTargetDependentFunctionAttr, METH_VARARGS, "Wrapper for LLVMAddTargetDependentFunctionAttr"},
	{"GetFunctionAttr", (PyCFunction)&Py_LLVMValue_GetFunctionAttr, METH_NOARGS, "Wrapper for LLVMGetFunctionAttr"},
	{"RemoveFunctionAttr", (PyCFunction)&Py_LLVMValue_RemoveFunctionAttr, METH_VARARGS, "Wrapper for LLVMRemoveFunctionAttr"},
	{"CountParams", (PyCFunction)&Py_LLVMValue_CountParams, METH_NOARGS, "Wrapper for LLVMCountParams"},
	{"GetParam", (PyCFunction)&Py_LLVMValue_GetParam, METH_VARARGS, "Wrapper for LLVMGetParam"},
	{"GetParamParent", (PyCFunction)&Py_LLVMValue_GetParamParent, METH_NOARGS, "Wrapper for LLVMGetParamParent"},
	{"GetFirstParam", (PyCFunction)&Py_LLVMValue_GetFirstParam, METH_NOARGS, "Wrapper for LLVMGetFirstParam"},
	{"GetLastParam", (PyCFunction)&Py_LLVMValue_GetLastParam, METH_NOARGS, "Wrapper for LLVMGetLastParam"},
	{"GetNextParam", (PyCFunction)&Py_LLVMValue_GetNextParam, METH_NOARGS, "Wrapper for LLVMGetNextParam"},
	{"GetPreviousParam", (PyCFunction)&Py_LLVMValue_GetPreviousParam, METH_NOARGS, "Wrapper for LLVMGetPreviousParam"},
	{"AddAttribute", (PyCFunction)&Py_LLVMValue_AddAttribute, METH_VARARGS, "Wrapper for LLVMAddAttribute"},
	{"RemoveAttribute", (PyCFunction)&Py_LLVMValue_RemoveAttribute, METH_VARARGS, "Wrapper for LLVMRemoveAttribute"},
	{"GetAttribute", (PyCFunction)&Py_LLVMValue_GetAttribute, METH_NOARGS, "Wrapper for LLVMGetAttribute"},
	{"SetParamAlignment", (PyCFunction)&Py_LLVMValue_SetParamAlignment, METH_VARARGS, "Wrapper for LLVMSetParamAlignment"},
	{"GetMDNodeNumOperands", (PyCFunction)&Py_LLVMValue_GetMDNodeNumOperands, METH_NOARGS, "Wrapper for LLVMGetMDNodeNumOperands"},
	{"ValueIsBasicBlock", (PyCFunction)&Py_LLVMValue_ValueIsBasicBlock, METH_NOARGS, "Wrapper for LLVMValueIsBasicBlock"},
	{"ValueAsBasicBlock", (PyCFunction)&Py_LLVMValue_ValueAsBasicBlock, METH_NOARGS, "Wrapper for LLVMValueAsBasicBlock"},
	{"CountBasicBlocks", (PyCFunction)&Py_LLVMValue_CountBasicBlocks, METH_NOARGS, "Wrapper for LLVMCountBasicBlocks"},
	{"GetFirstBasicBlock", (PyCFunction)&Py_LLVMValue_GetFirstBasicBlock, METH_NOARGS, "Wrapper for LLVMGetFirstBasicBlock"},
	{"GetLastBasicBlock", (PyCFunction)&Py_LLVMValue_GetLastBasicBlock, METH_NOARGS, "Wrapper for LLVMGetLastBasicBlock"},
	{"GetEntryBasicBlock", (PyCFunction)&Py_LLVMValue_GetEntryBasicBlock, METH_NOARGS, "Wrapper for LLVMGetEntryBasicBlock"},
	{"AppendBasicBlock", (PyCFunction)&Py_LLVMValue_AppendBasicBlock, METH_VARARGS, "Wrapper for LLVMAppendBasicBlock"},
	{"GetMetadata", (PyCFunction)&Py_LLVMValue_GetMetadata, METH_VARARGS, "Wrapper for LLVMGetMetadata"},
	{"SetMetadata", (PyCFunction)&Py_LLVMValue_SetMetadata, METH_VARARGS, "Wrapper for LLVMSetMetadata"},
	{"GetInstructionParent", (PyCFunction)&Py_LLVMValue_GetInstructionParent, METH_NOARGS, "Wrapper for LLVMGetInstructionParent"},
	{"GetNextInstruction", (PyCFunction)&Py_LLVMValue_GetNextInstruction, METH_NOARGS, "Wrapper for LLVMGetNextInstruction"},
	{"GetPreviousInstruction", (PyCFunction)&Py_LLVMValue_GetPreviousInstruction, METH_NOARGS, "Wrapper for LLVMGetPreviousInstruction"},
	{"InstructionEraseFromParent", (PyCFunction)&Py_LLVMValue_InstructionEraseFromParent, METH_NOARGS, "Wrapper for LLVMInstructionEraseFromParent"},
	{"GetInstructionOpcode", (PyCFunction)&Py_LLVMValue_GetInstructionOpcode, METH_NOARGS, "Wrapper for LLVMGetInstructionOpcode"},
	{"GetICmpPredicate", (PyCFunction)&Py_LLVMValue_GetICmpPredicate, METH_NOARGS, "Wrapper for LLVMGetICmpPredicate"},
	{"GetFCmpPredicate", (PyCFunction)&Py_LLVMValue_GetFCmpPredicate, METH_NOARGS, "Wrapper for LLVMGetFCmpPredicate"},
	{"InstructionClone", (PyCFunction)&Py_LLVMValue_InstructionClone, METH_NOARGS, "Wrapper for LLVMInstructionClone"},
	{"SetInstructionCallConv", (PyCFunction)&Py_LLVMValue_SetInstructionCallConv, METH_VARARGS, "Wrapper for LLVMSetInstructionCallConv"},
	{"GetInstructionCallConv", (PyCFunction)&Py_LLVMValue_GetInstructionCallConv, METH_NOARGS, "Wrapper for LLVMGetInstructionCallConv"},
	{"AddInstrAttribute", (PyCFunction)&Py_LLVMValue_AddInstrAttribute, METH_VARARGS, "Wrapper for LLVMAddInstrAttribute"},
	{"RemoveInstrAttribute", (PyCFunction)&Py_LLVMValue_RemoveInstrAttribute, METH_VARARGS, "Wrapper for LLVMRemoveInstrAttribute"},
	{"SetInstrParamAlignment", (PyCFunction)&Py_LLVMValue_SetInstrParamAlignment, METH_VARARGS, "Wrapper for LLVMSetInstrParamAlignment"},
	{"IsTailCall", (PyCFunction)&Py_LLVMValue_IsTailCall, METH_NOARGS, "Wrapper for LLVMIsTailCall"},
	{"SetTailCall", (PyCFunction)&Py_LLVMValue_SetTailCall, METH_VARARGS, "Wrapper for LLVMSetTailCall"},
	{"GetNumSuccessors", (PyCFunction)&Py_LLVMValue_GetNumSuccessors, METH_NOARGS, "Wrapper for LLVMGetNumSuccessors"},
	{"GetSuccessor", (PyCFunction)&Py_LLVMValue_GetSuccessor, METH_VARARGS, "Wrapper for LLVMGetSuccessor"},
	{"SetSuccessor", (PyCFunction)&Py_LLVMValue_SetSuccessor, METH_VARARGS, "Wrapper for LLVMSetSuccessor"},
	{"IsConditional", (PyCFunction)&Py_LLVMValue_IsConditional, METH_NOARGS, "Wrapper for LLVMIsConditional"},
	{"GetCondition", (PyCFunction)&Py_LLVMValue_GetCondition, METH_NOARGS, "Wrapper for LLVMGetCondition"},
	{"SetCondition", (PyCFunction)&Py_LLVMValue_SetCondition, METH_VARARGS, "Wrapper for LLVMSetCondition"},
	{"GetSwitchDefaultDest", (PyCFunction)&Py_LLVMValue_GetSwitchDefaultDest, METH_NOARGS, "Wrapper for LLVMGetSwitchDefaultDest"},
	{"CountIncoming", (PyCFunction)&Py_LLVMValue_CountIncoming, METH_NOARGS, "Wrapper for LLVMCountIncoming"},
	{"GetIncomingValue", (PyCFunction)&Py_LLVMValue_GetIncomingValue, METH_VARARGS, "Wrapper for LLVMGetIncomingValue"},
	{"GetIncomingBlock", (PyCFunction)&Py_LLVMValue_GetIncomingBlock, METH_VARARGS, "Wrapper for LLVMGetIncomingBlock"},
	{"AddCase", (PyCFunction)&Py_LLVMValue_AddCase, METH_VARARGS, "Wrapper for LLVMAddCase"},
	{"AddDestination", (PyCFunction)&Py_LLVMValue_AddDestination, METH_VARARGS, "Wrapper for LLVMAddDestination"},
	{"AddClause", (PyCFunction)&Py_LLVMValue_AddClause, METH_VARARGS, "Wrapper for LLVMAddClause"},
	{"SetCleanup", (PyCFunction)&Py_LLVMValue_SetCleanup, METH_VARARGS, "Wrapper for LLVMSetCleanup"},
	{"GetVolatile", (PyCFunction)&Py_LLVMValue_GetVolatile, METH_NOARGS, "Wrapper for LLVMGetVolatile"},
	{"SetVolatile", (PyCFunction)&Py_LLVMValue_SetVolatile, METH_VARARGS, "Wrapper for LLVMSetVolatile"},
	{nullptr}
};

PyTypeObject Py_LLVMValue_Type = {
	PyObject_HEAD_INIT(nullptr)
	.tp_name = "llvm.Value",
	.tp_basicsize = sizeof(Py_LLVM_Wrapped<LLVMValueRef>),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "Wrapper type for LLVMValueRef",
	.tp_methods = Py_LLVMValue_methods,
};

static PyObject* Py_LLVMPassRegistry_InitializeCore(Py_LLVM_Wrapped<LLVMPassRegistryRef>* self);

static PyMethodDef Py_LLVMPassRegistry_methods[] = {
	{"InitializeCore", (PyCFunction)&Py_LLVMPassRegistry_InitializeCore, METH_NOARGS, "Wrapper for LLVMInitializeCore"},
	{nullptr}
};

PyTypeObject Py_LLVMPassRegistry_Type = {
	PyObject_HEAD_INIT(nullptr)
	.tp_name = "llvm.PassRegistry",
	.tp_basicsize = sizeof(Py_LLVM_Wrapped<LLVMPassRegistryRef>),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "Wrapper type for LLVMPassRegistryRef",
	.tp_methods = Py_LLVMPassRegistry_methods,
};

static PyObject* Py_LLVMPassManager_RunPassManager(Py_LLVM_Wrapped<LLVMPassManagerRef>* self, PyObject* args);
static PyObject* Py_LLVMPassManager_InitializeFunctionPassManager(Py_LLVM_Wrapped<LLVMPassManagerRef>* self);
static PyObject* Py_LLVMPassManager_RunFunctionPassManager(Py_LLVM_Wrapped<LLVMPassManagerRef>* self, PyObject* args);
static PyObject* Py_LLVMPassManager_FinalizeFunctionPassManager(Py_LLVM_Wrapped<LLVMPassManagerRef>* self);
static PyObject* Py_LLVMPassManager_DisposePassManager(Py_LLVM_Wrapped<LLVMPassManagerRef>* self);

static PyMethodDef Py_LLVMPassManager_methods[] = {
	{"RunPassManager", (PyCFunction)&Py_LLVMPassManager_RunPassManager, METH_VARARGS, "Wrapper for LLVMRunPassManager"},
	{"InitializeFunctionPassManager", (PyCFunction)&Py_LLVMPassManager_InitializeFunctionPassManager, METH_NOARGS, "Wrapper for LLVMInitializeFunctionPassManager"},
	{"RunFunctionPassManager", (PyCFunction)&Py_LLVMPassManager_RunFunctionPassManager, METH_VARARGS, "Wrapper for LLVMRunFunctionPassManager"},
	{"FinalizeFunctionPassManager", (PyCFunction)&Py_LLVMPassManager_FinalizeFunctionPassManager, METH_NOARGS, "Wrapper for LLVMFinalizeFunctionPassManager"},
	{"DisposePassManager", (PyCFunction)&Py_LLVMPassManager_DisposePassManager, METH_NOARGS, "Wrapper for LLVMDisposePassManager"},
	{nullptr}
};

PyTypeObject Py_LLVMPassManager_Type = {
	PyObject_HEAD_INIT(nullptr)
	.tp_name = "llvm.PassManager",
	.tp_basicsize = sizeof(Py_LLVM_Wrapped<LLVMPassManagerRef>),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "Wrapper type for LLVMPassManagerRef",
	.tp_methods = Py_LLVMPassManager_methods,
};

static PyObject* Py_LLVMModule_CloneModule(Py_LLVM_Wrapped<LLVMModuleRef>* self);
static PyObject* Py_LLVMModule_DisposeModule(Py_LLVM_Wrapped<LLVMModuleRef>* self);
static PyObject* Py_LLVMModule_GetDataLayout(Py_LLVM_Wrapped<LLVMModuleRef>* self);
static PyObject* Py_LLVMModule_SetDataLayout(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args);
static PyObject* Py_LLVMModule_GetTarget(Py_LLVM_Wrapped<LLVMModuleRef>* self);
static PyObject* Py_LLVMModule_SetTarget(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args);
static PyObject* Py_LLVMModule_DumpModule(Py_LLVM_Wrapped<LLVMModuleRef>* self);
static PyObject* Py_LLVMModule_SetModuleInlineAsm(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args);
static PyObject* Py_LLVMModule_GetModuleContext(Py_LLVM_Wrapped<LLVMModuleRef>* self);
static PyObject* Py_LLVMModule_GetTypeByName(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args);
static PyObject* Py_LLVMModule_GetNamedMetadataNumOperands(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args);
static PyObject* Py_LLVMModule_AddNamedMetadataOperand(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args);
static PyObject* Py_LLVMModule_AddFunction(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args);
static PyObject* Py_LLVMModule_GetNamedFunction(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args);
static PyObject* Py_LLVMModule_GetFirstFunction(Py_LLVM_Wrapped<LLVMModuleRef>* self);
static PyObject* Py_LLVMModule_GetLastFunction(Py_LLVM_Wrapped<LLVMModuleRef>* self);
static PyObject* Py_LLVMModule_AddGlobal(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args);
static PyObject* Py_LLVMModule_AddGlobalInAddressSpace(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args);
static PyObject* Py_LLVMModule_GetNamedGlobal(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args);
static PyObject* Py_LLVMModule_GetFirstGlobal(Py_LLVM_Wrapped<LLVMModuleRef>* self);
static PyObject* Py_LLVMModule_GetLastGlobal(Py_LLVM_Wrapped<LLVMModuleRef>* self);
static PyObject* Py_LLVMModule_AddAlias(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args);
static PyObject* Py_LLVMModule_CreateModuleProviderForExistingModule(Py_LLVM_Wrapped<LLVMModuleRef>* self);
static PyObject* Py_LLVMModule_CreateFunctionPassManagerForModule(Py_LLVM_Wrapped<LLVMModuleRef>* self);

static PyMethodDef Py_LLVMModule_methods[] = {
	{"CloneModule", (PyCFunction)&Py_LLVMModule_CloneModule, METH_NOARGS, "Wrapper for LLVMCloneModule"},
	{"DisposeModule", (PyCFunction)&Py_LLVMModule_DisposeModule, METH_NOARGS, "Wrapper for LLVMDisposeModule"},
	{"GetDataLayout", (PyCFunction)&Py_LLVMModule_GetDataLayout, METH_NOARGS, "Wrapper for LLVMGetDataLayout"},
	{"SetDataLayout", (PyCFunction)&Py_LLVMModule_SetDataLayout, METH_VARARGS, "Wrapper for LLVMSetDataLayout"},
	{"GetTarget", (PyCFunction)&Py_LLVMModule_GetTarget, METH_NOARGS, "Wrapper for LLVMGetTarget"},
	{"SetTarget", (PyCFunction)&Py_LLVMModule_SetTarget, METH_VARARGS, "Wrapper for LLVMSetTarget"},
	{"DumpModule", (PyCFunction)&Py_LLVMModule_DumpModule, METH_NOARGS, "Wrapper for LLVMDumpModule"},
	{"SetModuleInlineAsm", (PyCFunction)&Py_LLVMModule_SetModuleInlineAsm, METH_VARARGS, "Wrapper for LLVMSetModuleInlineAsm"},
	{"GetModuleContext", (PyCFunction)&Py_LLVMModule_GetModuleContext, METH_NOARGS, "Wrapper for LLVMGetModuleContext"},
	{"GetTypeByName", (PyCFunction)&Py_LLVMModule_GetTypeByName, METH_VARARGS, "Wrapper for LLVMGetTypeByName"},
	{"GetNamedMetadataNumOperands", (PyCFunction)&Py_LLVMModule_GetNamedMetadataNumOperands, METH_VARARGS, "Wrapper for LLVMGetNamedMetadataNumOperands"},
	{"AddNamedMetadataOperand", (PyCFunction)&Py_LLVMModule_AddNamedMetadataOperand, METH_VARARGS, "Wrapper for LLVMAddNamedMetadataOperand"},
	{"AddFunction", (PyCFunction)&Py_LLVMModule_AddFunction, METH_VARARGS, "Wrapper for LLVMAddFunction"},
	{"GetNamedFunction", (PyCFunction)&Py_LLVMModule_GetNamedFunction, METH_VARARGS, "Wrapper for LLVMGetNamedFunction"},
	{"GetFirstFunction", (PyCFunction)&Py_LLVMModule_GetFirstFunction, METH_NOARGS, "Wrapper for LLVMGetFirstFunction"},
	{"GetLastFunction", (PyCFunction)&Py_LLVMModule_GetLastFunction, METH_NOARGS, "Wrapper for LLVMGetLastFunction"},
	{"AddGlobal", (PyCFunction)&Py_LLVMModule_AddGlobal, METH_VARARGS, "Wrapper for LLVMAddGlobal"},
	{"AddGlobalInAddressSpace", (PyCFunction)&Py_LLVMModule_AddGlobalInAddressSpace, METH_VARARGS, "Wrapper for LLVMAddGlobalInAddressSpace"},
	{"GetNamedGlobal", (PyCFunction)&Py_LLVMModule_GetNamedGlobal, METH_VARARGS, "Wrapper for LLVMGetNamedGlobal"},
	{"GetFirstGlobal", (PyCFunction)&Py_LLVMModule_GetFirstGlobal, METH_NOARGS, "Wrapper for LLVMGetFirstGlobal"},
	{"GetLastGlobal", (PyCFunction)&Py_LLVMModule_GetLastGlobal, METH_NOARGS, "Wrapper for LLVMGetLastGlobal"},
	{"AddAlias", (PyCFunction)&Py_LLVMModule_AddAlias, METH_VARARGS, "Wrapper for LLVMAddAlias"},
	{"CreateModuleProviderForExistingModule", (PyCFunction)&Py_LLVMModule_CreateModuleProviderForExistingModule, METH_NOARGS, "Wrapper for LLVMCreateModuleProviderForExistingModule"},
	{"CreateFunctionPassManagerForModule", (PyCFunction)&Py_LLVMModule_CreateFunctionPassManagerForModule, METH_NOARGS, "Wrapper for LLVMCreateFunctionPassManagerForModule"},
	{nullptr}
};

PyTypeObject Py_LLVMModule_Type = {
	PyObject_HEAD_INIT(nullptr)
	.tp_name = "llvm.Module",
	.tp_basicsize = sizeof(Py_LLVM_Wrapped<LLVMModuleRef>),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "Wrapper type for LLVMModuleRef",
	.tp_methods = Py_LLVMModule_methods,
};

static PyObject* Py_LLVMContext_ContextDispose(Py_LLVM_Wrapped<LLVMContextRef>* self);
static PyObject* Py_LLVMContext_GetMDKindID(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args);
static PyObject* Py_LLVMContext_Int1Type(Py_LLVM_Wrapped<LLVMContextRef>* self);
static PyObject* Py_LLVMContext_Int8Type(Py_LLVM_Wrapped<LLVMContextRef>* self);
static PyObject* Py_LLVMContext_Int16Type(Py_LLVM_Wrapped<LLVMContextRef>* self);
static PyObject* Py_LLVMContext_Int32Type(Py_LLVM_Wrapped<LLVMContextRef>* self);
static PyObject* Py_LLVMContext_Int64Type(Py_LLVM_Wrapped<LLVMContextRef>* self);
static PyObject* Py_LLVMContext_IntType(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args);
static PyObject* Py_LLVMContext_HalfType(Py_LLVM_Wrapped<LLVMContextRef>* self);
static PyObject* Py_LLVMContext_FloatType(Py_LLVM_Wrapped<LLVMContextRef>* self);
static PyObject* Py_LLVMContext_DoubleType(Py_LLVM_Wrapped<LLVMContextRef>* self);
static PyObject* Py_LLVMContext_X86FP80Type(Py_LLVM_Wrapped<LLVMContextRef>* self);
static PyObject* Py_LLVMContext_FP128Type(Py_LLVM_Wrapped<LLVMContextRef>* self);
static PyObject* Py_LLVMContext_PPCFP128Type(Py_LLVM_Wrapped<LLVMContextRef>* self);
static PyObject* Py_LLVMContext_StructType(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args);
static PyObject* Py_LLVMContext_StructCreateNamed(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args);
static PyObject* Py_LLVMContext_VoidType(Py_LLVM_Wrapped<LLVMContextRef>* self);
static PyObject* Py_LLVMContext_LabelType(Py_LLVM_Wrapped<LLVMContextRef>* self);
static PyObject* Py_LLVMContext_X86MMXType(Py_LLVM_Wrapped<LLVMContextRef>* self);
static PyObject* Py_LLVMContext_ConstString(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args);
static PyObject* Py_LLVMContext_ConstStruct(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args);
static PyObject* Py_LLVMContext_MDString(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args);
static PyObject* Py_LLVMContext_MDNode(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args);
static PyObject* Py_LLVMContext_AppendBasicBlock(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args);
static PyObject* Py_LLVMContext_InsertBasicBlock(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args);
static PyObject* Py_LLVMContext_CreateBuilder(Py_LLVM_Wrapped<LLVMContextRef>* self);

static PyMethodDef Py_LLVMContext_methods[] = {
	{"ContextDispose", (PyCFunction)&Py_LLVMContext_ContextDispose, METH_NOARGS, "Wrapper for LLVMContextDispose"},
	{"GetMDKindID", (PyCFunction)&Py_LLVMContext_GetMDKindID, METH_VARARGS, "Wrapper for LLVMGetMDKindIDInContext"},
	{"Int1Type", (PyCFunction)&Py_LLVMContext_Int1Type, METH_NOARGS, "Wrapper for LLVMInt1TypeInContext"},
	{"Int8Type", (PyCFunction)&Py_LLVMContext_Int8Type, METH_NOARGS, "Wrapper for LLVMInt8TypeInContext"},
	{"Int16Type", (PyCFunction)&Py_LLVMContext_Int16Type, METH_NOARGS, "Wrapper for LLVMInt16TypeInContext"},
	{"Int32Type", (PyCFunction)&Py_LLVMContext_Int32Type, METH_NOARGS, "Wrapper for LLVMInt32TypeInContext"},
	{"Int64Type", (PyCFunction)&Py_LLVMContext_Int64Type, METH_NOARGS, "Wrapper for LLVMInt64TypeInContext"},
	{"IntType", (PyCFunction)&Py_LLVMContext_IntType, METH_VARARGS, "Wrapper for LLVMIntTypeInContext"},
	{"HalfType", (PyCFunction)&Py_LLVMContext_HalfType, METH_NOARGS, "Wrapper for LLVMHalfTypeInContext"},
	{"FloatType", (PyCFunction)&Py_LLVMContext_FloatType, METH_NOARGS, "Wrapper for LLVMFloatTypeInContext"},
	{"DoubleType", (PyCFunction)&Py_LLVMContext_DoubleType, METH_NOARGS, "Wrapper for LLVMDoubleTypeInContext"},
	{"X86FP80Type", (PyCFunction)&Py_LLVMContext_X86FP80Type, METH_NOARGS, "Wrapper for LLVMX86FP80TypeInContext"},
	{"FP128Type", (PyCFunction)&Py_LLVMContext_FP128Type, METH_NOARGS, "Wrapper for LLVMFP128TypeInContext"},
	{"PPCFP128Type", (PyCFunction)&Py_LLVMContext_PPCFP128Type, METH_NOARGS, "Wrapper for LLVMPPCFP128TypeInContext"},
	{"StructType", (PyCFunction)&Py_LLVMContext_StructType, METH_VARARGS, "Wrapper for LLVMStructTypeInContext"},
	{"StructCreateNamed", (PyCFunction)&Py_LLVMContext_StructCreateNamed, METH_VARARGS, "Wrapper for LLVMStructCreateNamed"},
	{"VoidType", (PyCFunction)&Py_LLVMContext_VoidType, METH_NOARGS, "Wrapper for LLVMVoidTypeInContext"},
	{"LabelType", (PyCFunction)&Py_LLVMContext_LabelType, METH_NOARGS, "Wrapper for LLVMLabelTypeInContext"},
	{"X86MMXType", (PyCFunction)&Py_LLVMContext_X86MMXType, METH_NOARGS, "Wrapper for LLVMX86MMXTypeInContext"},
	{"ConstString", (PyCFunction)&Py_LLVMContext_ConstString, METH_VARARGS, "Wrapper for LLVMConstStringInContext"},
	{"ConstStruct", (PyCFunction)&Py_LLVMContext_ConstStruct, METH_VARARGS, "Wrapper for LLVMConstStructInContext"},
	{"MDString", (PyCFunction)&Py_LLVMContext_MDString, METH_VARARGS, "Wrapper for LLVMMDStringInContext"},
	{"MDNode", (PyCFunction)&Py_LLVMContext_MDNode, METH_VARARGS, "Wrapper for LLVMMDNodeInContext"},
	{"AppendBasicBlock", (PyCFunction)&Py_LLVMContext_AppendBasicBlock, METH_VARARGS, "Wrapper for LLVMAppendBasicBlockInContext"},
	{"InsertBasicBlock", (PyCFunction)&Py_LLVMContext_InsertBasicBlock, METH_VARARGS, "Wrapper for LLVMInsertBasicBlockInContext"},
	{"CreateBuilder", (PyCFunction)&Py_LLVMContext_CreateBuilder, METH_NOARGS, "Wrapper for LLVMCreateBuilderInContext"},
	{nullptr}
};

PyTypeObject Py_LLVMContext_Type = {
	PyObject_HEAD_INIT(nullptr)
	.tp_name = "llvm.Context",
	.tp_basicsize = sizeof(Py_LLVM_Wrapped<LLVMContextRef>),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "Wrapper type for LLVMContextRef",
	.tp_methods = Py_LLVMContext_methods,
};

static PyObject* Py_LLVMDiagnosticInfo_GetDiagInfoSeverity(Py_LLVM_Wrapped<LLVMDiagnosticInfoRef>* self);

static PyMethodDef Py_LLVMDiagnosticInfo_methods[] = {
	{"GetDiagInfoSeverity", (PyCFunction)&Py_LLVMDiagnosticInfo_GetDiagInfoSeverity, METH_NOARGS, "Wrapper for LLVMGetDiagInfoSeverity"},
	{nullptr}
};

PyTypeObject Py_LLVMDiagnosticInfo_Type = {
	PyObject_HEAD_INIT(nullptr)
	.tp_name = "llvm.DiagnosticInfo",
	.tp_basicsize = sizeof(Py_LLVM_Wrapped<LLVMDiagnosticInfoRef>),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "Wrapper type for LLVMDiagnosticInfoRef",
	.tp_methods = Py_LLVMDiagnosticInfo_methods,
};

static PyObject* Py_LLVMBasicBlock_BasicBlockAsValue(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self);
static PyObject* Py_LLVMBasicBlock_GetBasicBlockParent(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self);
static PyObject* Py_LLVMBasicBlock_GetBasicBlockTerminator(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self);
static PyObject* Py_LLVMBasicBlock_GetNextBasicBlock(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self);
static PyObject* Py_LLVMBasicBlock_GetPreviousBasicBlock(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self);
static PyObject* Py_LLVMBasicBlock_InsertBasicBlock(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self, PyObject* args);
static PyObject* Py_LLVMBasicBlock_DeleteBasicBlock(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self);
static PyObject* Py_LLVMBasicBlock_RemoveBasicBlockFromParent(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self);
static PyObject* Py_LLVMBasicBlock_MoveBasicBlockBefore(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self, PyObject* args);
static PyObject* Py_LLVMBasicBlock_MoveBasicBlockAfter(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self, PyObject* args);
static PyObject* Py_LLVMBasicBlock_GetFirstInstruction(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self);
static PyObject* Py_LLVMBasicBlock_GetLastInstruction(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self);

static PyMethodDef Py_LLVMBasicBlock_methods[] = {
	{"BasicBlockAsValue", (PyCFunction)&Py_LLVMBasicBlock_BasicBlockAsValue, METH_NOARGS, "Wrapper for LLVMBasicBlockAsValue"},
	{"GetBasicBlockParent", (PyCFunction)&Py_LLVMBasicBlock_GetBasicBlockParent, METH_NOARGS, "Wrapper for LLVMGetBasicBlockParent"},
	{"GetBasicBlockTerminator", (PyCFunction)&Py_LLVMBasicBlock_GetBasicBlockTerminator, METH_NOARGS, "Wrapper for LLVMGetBasicBlockTerminator"},
	{"GetNextBasicBlock", (PyCFunction)&Py_LLVMBasicBlock_GetNextBasicBlock, METH_NOARGS, "Wrapper for LLVMGetNextBasicBlock"},
	{"GetPreviousBasicBlock", (PyCFunction)&Py_LLVMBasicBlock_GetPreviousBasicBlock, METH_NOARGS, "Wrapper for LLVMGetPreviousBasicBlock"},
	{"InsertBasicBlock", (PyCFunction)&Py_LLVMBasicBlock_InsertBasicBlock, METH_VARARGS, "Wrapper for LLVMInsertBasicBlock"},
	{"DeleteBasicBlock", (PyCFunction)&Py_LLVMBasicBlock_DeleteBasicBlock, METH_NOARGS, "Wrapper for LLVMDeleteBasicBlock"},
	{"RemoveBasicBlockFromParent", (PyCFunction)&Py_LLVMBasicBlock_RemoveBasicBlockFromParent, METH_NOARGS, "Wrapper for LLVMRemoveBasicBlockFromParent"},
	{"MoveBasicBlockBefore", (PyCFunction)&Py_LLVMBasicBlock_MoveBasicBlockBefore, METH_VARARGS, "Wrapper for LLVMMoveBasicBlockBefore"},
	{"MoveBasicBlockAfter", (PyCFunction)&Py_LLVMBasicBlock_MoveBasicBlockAfter, METH_VARARGS, "Wrapper for LLVMMoveBasicBlockAfter"},
	{"GetFirstInstruction", (PyCFunction)&Py_LLVMBasicBlock_GetFirstInstruction, METH_NOARGS, "Wrapper for LLVMGetFirstInstruction"},
	{"GetLastInstruction", (PyCFunction)&Py_LLVMBasicBlock_GetLastInstruction, METH_NOARGS, "Wrapper for LLVMGetLastInstruction"},
	{nullptr}
};

PyTypeObject Py_LLVMBasicBlock_Type = {
	PyObject_HEAD_INIT(nullptr)
	.tp_name = "llvm.BasicBlock",
	.tp_basicsize = sizeof(Py_LLVM_Wrapped<LLVMBasicBlockRef>),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "Wrapper type for LLVMBasicBlockRef",
	.tp_methods = Py_LLVMBasicBlock_methods,
};

static PyObject* Py_LLVMType_GetTypeKind(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_TypeIsSized(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_GetTypeContext(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_DumpType(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_GetIntTypeWidth(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_FunctionType(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args);
static PyObject* Py_LLVMType_IsFunctionVarArg(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_GetReturnType(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_CountParamTypes(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_GetStructName(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_StructSetBody(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args);
static PyObject* Py_LLVMType_CountStructElementTypes(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_StructGetTypeAtIndex(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args);
static PyObject* Py_LLVMType_IsPackedStruct(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_IsOpaqueStruct(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_GetElementType(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_ArrayType(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args);
static PyObject* Py_LLVMType_GetArrayLength(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_PointerType(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args);
static PyObject* Py_LLVMType_GetPointerAddressSpace(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_VectorType(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args);
static PyObject* Py_LLVMType_GetVectorSize(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_ConstNull(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_ConstAllOnes(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_GetUndef(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_ConstPointerNull(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_ConstRealOfString(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args);
static PyObject* Py_LLVMType_ConstRealOfStringAndSize(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args);
static PyObject* Py_LLVMType_ConstArray(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args);
static PyObject* Py_LLVMType_ConstNamedStruct(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args);
static PyObject* Py_LLVMType_AlignOf(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_SizeOf(Py_LLVM_Wrapped<LLVMTypeRef>* self);
static PyObject* Py_LLVMType_ConstInlineAsm(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args);

static PyMethodDef Py_LLVMType_methods[] = {
	{"GetTypeKind", (PyCFunction)&Py_LLVMType_GetTypeKind, METH_NOARGS, "Wrapper for LLVMGetTypeKind"},
	{"TypeIsSized", (PyCFunction)&Py_LLVMType_TypeIsSized, METH_NOARGS, "Wrapper for LLVMTypeIsSized"},
	{"GetTypeContext", (PyCFunction)&Py_LLVMType_GetTypeContext, METH_NOARGS, "Wrapper for LLVMGetTypeContext"},
	{"DumpType", (PyCFunction)&Py_LLVMType_DumpType, METH_NOARGS, "Wrapper for LLVMDumpType"},
	{"GetIntTypeWidth", (PyCFunction)&Py_LLVMType_GetIntTypeWidth, METH_NOARGS, "Wrapper for LLVMGetIntTypeWidth"},
	{"FunctionType", (PyCFunction)&Py_LLVMType_FunctionType, METH_VARARGS, "Wrapper for LLVMFunctionType"},
	{"IsFunctionVarArg", (PyCFunction)&Py_LLVMType_IsFunctionVarArg, METH_NOARGS, "Wrapper for LLVMIsFunctionVarArg"},
	{"GetReturnType", (PyCFunction)&Py_LLVMType_GetReturnType, METH_NOARGS, "Wrapper for LLVMGetReturnType"},
	{"CountParamTypes", (PyCFunction)&Py_LLVMType_CountParamTypes, METH_NOARGS, "Wrapper for LLVMCountParamTypes"},
	{"GetStructName", (PyCFunction)&Py_LLVMType_GetStructName, METH_NOARGS, "Wrapper for LLVMGetStructName"},
	{"StructSetBody", (PyCFunction)&Py_LLVMType_StructSetBody, METH_VARARGS, "Wrapper for LLVMStructSetBody"},
	{"CountStructElementTypes", (PyCFunction)&Py_LLVMType_CountStructElementTypes, METH_NOARGS, "Wrapper for LLVMCountStructElementTypes"},
	{"StructGetTypeAtIndex", (PyCFunction)&Py_LLVMType_StructGetTypeAtIndex, METH_VARARGS, "Wrapper for LLVMStructGetTypeAtIndex"},
	{"IsPackedStruct", (PyCFunction)&Py_LLVMType_IsPackedStruct, METH_NOARGS, "Wrapper for LLVMIsPackedStruct"},
	{"IsOpaqueStruct", (PyCFunction)&Py_LLVMType_IsOpaqueStruct, METH_NOARGS, "Wrapper for LLVMIsOpaqueStruct"},
	{"GetElementType", (PyCFunction)&Py_LLVMType_GetElementType, METH_NOARGS, "Wrapper for LLVMGetElementType"},
	{"ArrayType", (PyCFunction)&Py_LLVMType_ArrayType, METH_VARARGS, "Wrapper for LLVMArrayType"},
	{"GetArrayLength", (PyCFunction)&Py_LLVMType_GetArrayLength, METH_NOARGS, "Wrapper for LLVMGetArrayLength"},
	{"PointerType", (PyCFunction)&Py_LLVMType_PointerType, METH_VARARGS, "Wrapper for LLVMPointerType"},
	{"GetPointerAddressSpace", (PyCFunction)&Py_LLVMType_GetPointerAddressSpace, METH_NOARGS, "Wrapper for LLVMGetPointerAddressSpace"},
	{"VectorType", (PyCFunction)&Py_LLVMType_VectorType, METH_VARARGS, "Wrapper for LLVMVectorType"},
	{"GetVectorSize", (PyCFunction)&Py_LLVMType_GetVectorSize, METH_NOARGS, "Wrapper for LLVMGetVectorSize"},
	{"ConstNull", (PyCFunction)&Py_LLVMType_ConstNull, METH_NOARGS, "Wrapper for LLVMConstNull"},
	{"ConstAllOnes", (PyCFunction)&Py_LLVMType_ConstAllOnes, METH_NOARGS, "Wrapper for LLVMConstAllOnes"},
	{"GetUndef", (PyCFunction)&Py_LLVMType_GetUndef, METH_NOARGS, "Wrapper for LLVMGetUndef"},
	{"ConstPointerNull", (PyCFunction)&Py_LLVMType_ConstPointerNull, METH_NOARGS, "Wrapper for LLVMConstPointerNull"},
	{"ConstRealOfString", (PyCFunction)&Py_LLVMType_ConstRealOfString, METH_VARARGS, "Wrapper for LLVMConstRealOfString"},
	{"ConstRealOfStringAndSize", (PyCFunction)&Py_LLVMType_ConstRealOfStringAndSize, METH_VARARGS, "Wrapper for LLVMConstRealOfStringAndSize"},
	{"ConstArray", (PyCFunction)&Py_LLVMType_ConstArray, METH_VARARGS, "Wrapper for LLVMConstArray"},
	{"ConstNamedStruct", (PyCFunction)&Py_LLVMType_ConstNamedStruct, METH_VARARGS, "Wrapper for LLVMConstNamedStruct"},
	{"AlignOf", (PyCFunction)&Py_LLVMType_AlignOf, METH_NOARGS, "Wrapper for LLVMAlignOf"},
	{"SizeOf", (PyCFunction)&Py_LLVMType_SizeOf, METH_NOARGS, "Wrapper for LLVMSizeOf"},
	{"ConstInlineAsm", (PyCFunction)&Py_LLVMType_ConstInlineAsm, METH_VARARGS, "Wrapper for LLVMConstInlineAsm"},
	{nullptr}
};

PyTypeObject Py_LLVMType_Type = {
	PyObject_HEAD_INIT(nullptr)
	.tp_name = "llvm.Type",
	.tp_basicsize = sizeof(Py_LLVM_Wrapped<LLVMTypeRef>),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "Wrapper type for LLVMTypeRef",
	.tp_methods = Py_LLVMType_methods,
};

static PyObject* Py_LLVMUse_GetNextUse(Py_LLVM_Wrapped<LLVMUseRef>* self)
{
	auto callReturn = LLVMGetNextUse(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMUseRef>* result = (Py_LLVM_Wrapped<LLVMUseRef>*)PyType_GenericNew(&Py_LLVMUse_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMUse_GetUser(Py_LLVM_Wrapped<LLVMUseRef>* self)
{
	auto callReturn = LLVMGetUser(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMUse_GetUsedValue(Py_LLVM_Wrapped<LLVMUseRef>* self)
{
	auto callReturn = LLVMGetUsedValue(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMModuleProvider_DisposeModuleProvider(Py_LLVM_Wrapped<LLVMModuleProviderRef>* self)
{
	LLVMDisposeModuleProvider(self->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMModuleProvider_CreateFunctionPassManager(Py_LLVM_Wrapped<LLVMModuleProviderRef>* self)
{
	auto callReturn = LLVMCreateFunctionPassManager(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMPassManagerRef>* result = (Py_LLVM_Wrapped<LLVMPassManagerRef>*)PyType_GenericNew(&Py_LLVMPassManager_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_PositionBuilder(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	if (!PyArg_ParseTuple(args, "O!O!", &Py_LLVMBasicBlock_Type, &arg0, &Py_LLVMValue_Type, &arg1))
	{
		return nullptr;
	}

	LLVMPositionBuilder(self->obj, arg0->obj, arg1->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMBuilder_PositionBuilderBefore(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMValue_Type, &arg0))
	{
		return nullptr;
	}

	LLVMPositionBuilderBefore(self->obj, arg0->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMBuilder_PositionBuilderAtEnd(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMBasicBlock_Type, &arg0))
	{
		return nullptr;
	}

	LLVMPositionBuilderAtEnd(self->obj, arg0->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMBuilder_GetInsertBlock(Py_LLVM_Wrapped<LLVMBuilderRef>* self)
{
	auto callReturn = LLVMGetInsertBlock(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* result = (Py_LLVM_Wrapped<LLVMBasicBlockRef>*)PyType_GenericNew(&Py_LLVMBasicBlock_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_ClearInsertionPosition(Py_LLVM_Wrapped<LLVMBuilderRef>* self)
{
	LLVMClearInsertionPosition(self->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMBuilder_InsertIntoBuilder(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMValue_Type, &arg0))
	{
		return nullptr;
	}

	LLVMInsertIntoBuilder(self->obj, arg0->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMBuilder_InsertIntoBuilderWithName(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "O!s", &Py_LLVMValue_Type, &arg0, &arg1))
	{
		return nullptr;
	}

	LLVMInsertIntoBuilderWithName(self->obj, arg0->obj, arg1);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMBuilder_DisposeBuilder(Py_LLVM_Wrapped<LLVMBuilderRef>* self)
{
	LLVMDisposeBuilder(self->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMBuilder_SetCurrentDebugLocation(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMValue_Type, &arg0))
	{
		return nullptr;
	}

	LLVMSetCurrentDebugLocation(self->obj, arg0->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMBuilder_GetCurrentDebugLocation(Py_LLVM_Wrapped<LLVMBuilderRef>* self)
{
	auto callReturn = LLVMGetCurrentDebugLocation(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_SetInstDebugLocation(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMValue_Type, &arg0))
	{
		return nullptr;
	}

	LLVMSetInstDebugLocation(self->obj, arg0->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMBuilder_BuildRetVoid(Py_LLVM_Wrapped<LLVMBuilderRef>* self)
{
	auto callReturn = LLVMBuildRetVoid(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildRet(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMValue_Type, &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildRet(self->obj, arg0->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildBr(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMBasicBlock_Type, &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildBr(self->obj, arg0->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildCondBr(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* arg1;
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* arg2;
	if (!PyArg_ParseTuple(args, "O!O!O!", &Py_LLVMValue_Type, &arg0, &Py_LLVMBasicBlock_Type, &arg1, &Py_LLVMBasicBlock_Type, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildCondBr(self->obj, arg0->obj, arg1->obj, arg2->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildSwitch(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* arg1;
	long long arg2;
	if (!PyArg_ParseTuple(args, "O!O!L", &Py_LLVMValue_Type, &arg0, &Py_LLVMBasicBlock_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildSwitch(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildIndirectBr(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	long long arg1;
	if (!PyArg_ParseTuple(args, "O!L", &Py_LLVMValue_Type, &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildIndirectBr(self->obj, arg0->obj, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildInvoke(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	PyObject* arg1;
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* arg2;
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* arg3;
	const char* arg4;
	if (!PyArg_ParseTuple(args, "O!OO!O!s", &Py_LLVMValue_Type, &arg0, &arg1, &Py_LLVMBasicBlock_Type, &arg2, &Py_LLVMBasicBlock_Type, &arg3, &arg4))
	{
		return nullptr;
	}

	auto seq1 = TAKEREF PySequence_Fast(arg1, "argument 2 expected to be a sequence");
	if (!seq1)
	{
		return nullptr;
	}
	Py_ssize_t len1 = PySequence_Size(seq1.get());
	std::unique_ptr<LLVMValueRef[]> array1(new LLVMValueRef[len1]);
	for (Py_ssize_t i = 0; i < len1; ++i)
	{
		auto wrapped = (Py_LLVM_Wrapped<LLVMValueRef>*)PySequence_Fast_GET_ITEM(seq1.get(), i);
		array1[i] = wrapped->obj;
	}
	auto callReturn = LLVMBuildInvoke(self->obj, arg0->obj, array1.get(), len1, arg2->obj, arg3->obj, arg4);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildLandingPad(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMTypeRef>* arg0;
	long long arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!Ls", &Py_LLVMType_Type, &arg0, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildLandingPad(self->obj, arg0->obj, arg1, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildResume(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMValue_Type, &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildResume(self->obj, arg0->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildUnreachable(Py_LLVM_Wrapped<LLVMBuilderRef>* self)
{
	auto callReturn = LLVMBuildUnreachable(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildAdd(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildAdd(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildNSWAdd(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildNSWAdd(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildNUWAdd(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildNUWAdd(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildFAdd(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildFAdd(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildSub(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildSub(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildNSWSub(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildNSWSub(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildNUWSub(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildNUWSub(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildFSub(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildFSub(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildMul(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildMul(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildNSWMul(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildNSWMul(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildNUWMul(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildNUWMul(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildFMul(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildFMul(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildUDiv(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildUDiv(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildSDiv(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildSDiv(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildExactSDiv(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildExactSDiv(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildFDiv(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildFDiv(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildURem(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildURem(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildSRem(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildSRem(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildFRem(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildFRem(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildShl(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildShl(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildLShr(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildLShr(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildAShr(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildAShr(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildAnd(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildAnd(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildOr(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildOr(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildXor(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildXor(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildBinOp(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	long long arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	Py_LLVM_Wrapped<LLVMValueRef>* arg2;
	const char* arg3;
	if (!PyArg_ParseTuple(args, "LO!O!s", &arg0, &Py_LLVMValue_Type, &arg1, &Py_LLVMValue_Type, &arg2, &arg3))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildBinOp(self->obj, (LLVMOpcode)arg0, arg1->obj, arg2->obj, arg3);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildNeg(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "O!s", &Py_LLVMValue_Type, &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildNeg(self->obj, arg0->obj, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildNSWNeg(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "O!s", &Py_LLVMValue_Type, &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildNSWNeg(self->obj, arg0->obj, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildNUWNeg(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "O!s", &Py_LLVMValue_Type, &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildNUWNeg(self->obj, arg0->obj, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildFNeg(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "O!s", &Py_LLVMValue_Type, &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildFNeg(self->obj, arg0->obj, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildNot(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "O!s", &Py_LLVMValue_Type, &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildNot(self->obj, arg0->obj, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildMalloc(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMTypeRef>* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "O!s", &Py_LLVMType_Type, &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildMalloc(self->obj, arg0->obj, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildArrayMalloc(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMTypeRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMType_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildArrayMalloc(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildAlloca(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMTypeRef>* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "O!s", &Py_LLVMType_Type, &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildAlloca(self->obj, arg0->obj, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildArrayAlloca(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMTypeRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMType_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildArrayAlloca(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildFree(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMValue_Type, &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildFree(self->obj, arg0->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildLoad(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "O!s", &Py_LLVMValue_Type, &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildLoad(self->obj, arg0->obj, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildStore(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	if (!PyArg_ParseTuple(args, "O!O!", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildStore(self->obj, arg0->obj, arg1->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildGEP(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	PyObject* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!Os", &Py_LLVMValue_Type, &arg0, &arg1, &arg2))
	{
		return nullptr;
	}

	auto seq1 = TAKEREF PySequence_Fast(arg1, "argument 2 expected to be a sequence");
	if (!seq1)
	{
		return nullptr;
	}
	Py_ssize_t len1 = PySequence_Size(seq1.get());
	std::unique_ptr<LLVMValueRef[]> array1(new LLVMValueRef[len1]);
	for (Py_ssize_t i = 0; i < len1; ++i)
	{
		auto wrapped = (Py_LLVM_Wrapped<LLVMValueRef>*)PySequence_Fast_GET_ITEM(seq1.get(), i);
		array1[i] = wrapped->obj;
	}
	auto callReturn = LLVMBuildGEP(self->obj, arg0->obj, array1.get(), len1, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildInBoundsGEP(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	PyObject* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!Os", &Py_LLVMValue_Type, &arg0, &arg1, &arg2))
	{
		return nullptr;
	}

	auto seq1 = TAKEREF PySequence_Fast(arg1, "argument 2 expected to be a sequence");
	if (!seq1)
	{
		return nullptr;
	}
	Py_ssize_t len1 = PySequence_Size(seq1.get());
	std::unique_ptr<LLVMValueRef[]> array1(new LLVMValueRef[len1]);
	for (Py_ssize_t i = 0; i < len1; ++i)
	{
		auto wrapped = (Py_LLVM_Wrapped<LLVMValueRef>*)PySequence_Fast_GET_ITEM(seq1.get(), i);
		array1[i] = wrapped->obj;
	}
	auto callReturn = LLVMBuildInBoundsGEP(self->obj, arg0->obj, array1.get(), len1, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildStructGEP(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	long long arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!Ls", &Py_LLVMValue_Type, &arg0, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildStructGEP(self->obj, arg0->obj, arg1, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildGlobalString(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	const char* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "ss", &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildGlobalString(self->obj, arg0, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildGlobalStringPtr(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	const char* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "ss", &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildGlobalStringPtr(self->obj, arg0, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildTrunc(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildTrunc(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildZExt(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildZExt(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildSExt(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildSExt(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildFPToUI(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildFPToUI(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildFPToSI(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildFPToSI(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildUIToFP(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildUIToFP(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildSIToFP(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildSIToFP(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildFPTrunc(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildFPTrunc(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildFPExt(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildFPExt(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildPtrToInt(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildPtrToInt(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildIntToPtr(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildIntToPtr(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildBitCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildBitCast(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildAddrSpaceCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildAddrSpaceCast(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildZExtOrBitCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildZExtOrBitCast(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildSExtOrBitCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildSExtOrBitCast(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildTruncOrBitCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildTruncOrBitCast(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	long long arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg2;
	const char* arg3;
	if (!PyArg_ParseTuple(args, "LO!O!s", &arg0, &Py_LLVMValue_Type, &arg1, &Py_LLVMType_Type, &arg2, &arg3))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildCast(self->obj, (LLVMOpcode)arg0, arg1->obj, arg2->obj, arg3);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildPointerCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildPointerCast(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildIntCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildIntCast(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildFPCast(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildFPCast(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildICmp(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	long long arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	Py_LLVM_Wrapped<LLVMValueRef>* arg2;
	const char* arg3;
	if (!PyArg_ParseTuple(args, "LO!O!s", &arg0, &Py_LLVMValue_Type, &arg1, &Py_LLVMValue_Type, &arg2, &arg3))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildICmp(self->obj, (LLVMIntPredicate)arg0, arg1->obj, arg2->obj, arg3);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildFCmp(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	long long arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	Py_LLVM_Wrapped<LLVMValueRef>* arg2;
	const char* arg3;
	if (!PyArg_ParseTuple(args, "LO!O!s", &arg0, &Py_LLVMValue_Type, &arg1, &Py_LLVMValue_Type, &arg2, &arg3))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildFCmp(self->obj, (LLVMRealPredicate)arg0, arg1->obj, arg2->obj, arg3);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildPhi(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMTypeRef>* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "O!s", &Py_LLVMType_Type, &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildPhi(self->obj, arg0->obj, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildCall(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	PyObject* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!Os", &Py_LLVMValue_Type, &arg0, &arg1, &arg2))
	{
		return nullptr;
	}

	auto seq1 = TAKEREF PySequence_Fast(arg1, "argument 2 expected to be a sequence");
	if (!seq1)
	{
		return nullptr;
	}
	Py_ssize_t len1 = PySequence_Size(seq1.get());
	std::unique_ptr<LLVMValueRef[]> array1(new LLVMValueRef[len1]);
	for (Py_ssize_t i = 0; i < len1; ++i)
	{
		auto wrapped = (Py_LLVM_Wrapped<LLVMValueRef>*)PySequence_Fast_GET_ITEM(seq1.get(), i);
		array1[i] = wrapped->obj;
	}
	auto callReturn = LLVMBuildCall(self->obj, arg0->obj, array1.get(), len1, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildSelect(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	Py_LLVM_Wrapped<LLVMValueRef>* arg2;
	const char* arg3;
	if (!PyArg_ParseTuple(args, "O!O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &Py_LLVMValue_Type, &arg2, &arg3))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildSelect(self->obj, arg0->obj, arg1->obj, arg2->obj, arg3);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildVAArg(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMType_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildVAArg(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildExtractElement(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildExtractElement(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildInsertElement(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	Py_LLVM_Wrapped<LLVMValueRef>* arg2;
	const char* arg3;
	if (!PyArg_ParseTuple(args, "O!O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &Py_LLVMValue_Type, &arg2, &arg3))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildInsertElement(self->obj, arg0->obj, arg1->obj, arg2->obj, arg3);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildShuffleVector(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	Py_LLVM_Wrapped<LLVMValueRef>* arg2;
	const char* arg3;
	if (!PyArg_ParseTuple(args, "O!O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &Py_LLVMValue_Type, &arg2, &arg3))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildShuffleVector(self->obj, arg0->obj, arg1->obj, arg2->obj, arg3);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildExtractValue(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	long long arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!Ls", &Py_LLVMValue_Type, &arg0, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildExtractValue(self->obj, arg0->obj, arg1, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildInsertValue(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	long long arg2;
	const char* arg3;
	if (!PyArg_ParseTuple(args, "O!O!Ls", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2, &arg3))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildInsertValue(self->obj, arg0->obj, arg1->obj, arg2, arg3);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildIsNull(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "O!s", &Py_LLVMValue_Type, &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildIsNull(self->obj, arg0->obj, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildIsNotNull(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "O!s", &Py_LLVMValue_Type, &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildIsNotNull(self->obj, arg0->obj, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildPtrDiff(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMValue_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMBuildPtrDiff(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildFence(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	long long arg0;
	PyObject* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "LO!s", &arg0, &PyBool_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	LLVMBool carg1 = PyObject_IsTrue(arg1);
	auto callReturn = LLVMBuildFence(self->obj, (LLVMAtomicOrdering)arg0, carg1, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBuilder_BuildAtomicRMW(Py_LLVM_Wrapped<LLVMBuilderRef>* self, PyObject* args)
{
	long long arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	Py_LLVM_Wrapped<LLVMValueRef>* arg2;
	long long arg3;
	PyObject* arg4;
	if (!PyArg_ParseTuple(args, "LO!O!LO!", &arg0, &Py_LLVMValue_Type, &arg1, &Py_LLVMValue_Type, &arg2, &arg3, &PyBool_Type, &arg4))
	{
		return nullptr;
	}

	LLVMBool carg4 = PyObject_IsTrue(arg4);
	auto callReturn = LLVMBuildAtomicRMW(self->obj, (LLVMAtomicRMWBinOp)arg0, arg1->obj, arg2->obj, (LLVMAtomicOrdering)arg3, carg4);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetNextFunction(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetNextFunction(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetPreviousFunction(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetPreviousFunction(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_TypeOf(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMTypeOf(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetValueName(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyString_FromString(LLVMGetValueName(self->obj));
}

static PyObject* Py_LLVMValue_SetValueName(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	const char* arg0;
	if (!PyArg_ParseTuple(args, "s", &arg0))
	{
		return nullptr;
	}

	LLVMSetValueName(self->obj, arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_DumpValue(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	LLVMDumpValue(self->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_ReplaceAllUsesWith(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMValue_Type, &arg0))
	{
		return nullptr;
	}

	LLVMReplaceAllUsesWith(self->obj, arg0->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_IsConstant(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyBool_FromLong(LLVMIsConstant(self->obj));
}

static PyObject* Py_LLVMValue_IsUndef(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyBool_FromLong(LLVMIsUndef(self->obj));
}

static PyObject* Py_LLVMValue_IsAArgument(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMIsAArgument(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_IsAMDNode(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMIsAMDNode(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_IsAMDString(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMIsAMDString(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetFirstUse(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetFirstUse(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMUseRef>* result = (Py_LLVM_Wrapped<LLVMUseRef>*)PyType_GenericNew(&Py_LLVMUse_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetOperand(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMGetOperand(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetOperandUse(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMGetOperandUse(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMUseRef>* result = (Py_LLVM_Wrapped<LLVMUseRef>*)PyType_GenericNew(&Py_LLVMUse_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_SetOperand(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	if (!PyArg_ParseTuple(args, "LO!", &arg0, &Py_LLVMValue_Type, &arg1))
	{
		return nullptr;
	}

	LLVMSetOperand(self->obj, arg0, arg1->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_IsNull(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyBool_FromLong(LLVMIsNull(self->obj));
}

static PyObject* Py_LLVMValue_IsConstantString(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyBool_FromLong(LLVMIsConstantString(self->obj));
}

static PyObject* Py_LLVMValue_GetElementAsConstant(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMGetElementAsConstant(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetConstOpcode(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMGetConstOpcode(self->obj));
}

static PyObject* Py_LLVMValue_BlockAddress(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMBasicBlock_Type, &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMBlockAddress(self->obj, arg0->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetGlobalParent(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetGlobalParent(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMModuleRef>* result = (Py_LLVM_Wrapped<LLVMModuleRef>*)PyType_GenericNew(&Py_LLVMModule_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_IsDeclaration(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyBool_FromLong(LLVMIsDeclaration(self->obj));
}

static PyObject* Py_LLVMValue_GetLinkage(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMGetLinkage(self->obj));
}

static PyObject* Py_LLVMValue_SetLinkage(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	LLVMSetLinkage(self->obj, (LLVMLinkage)arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetSection(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyString_FromString(LLVMGetSection(self->obj));
}

static PyObject* Py_LLVMValue_SetSection(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	const char* arg0;
	if (!PyArg_ParseTuple(args, "s", &arg0))
	{
		return nullptr;
	}

	LLVMSetSection(self->obj, arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetVisibility(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMGetVisibility(self->obj));
}

static PyObject* Py_LLVMValue_SetVisibility(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	LLVMSetVisibility(self->obj, (LLVMVisibility)arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetDLLStorageClass(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMGetDLLStorageClass(self->obj));
}

static PyObject* Py_LLVMValue_SetDLLStorageClass(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	LLVMSetDLLStorageClass(self->obj, (LLVMDLLStorageClass)arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_HasUnnamedAddr(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyBool_FromLong(LLVMHasUnnamedAddr(self->obj));
}

static PyObject* Py_LLVMValue_SetUnnamedAddr(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	PyObject* arg0;
	if (!PyArg_ParseTuple(args, "O!", &PyBool_Type, &arg0))
	{
		return nullptr;
	}

	LLVMBool carg0 = PyObject_IsTrue(arg0);
	LLVMSetUnnamedAddr(self->obj, carg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetAlignment(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMGetAlignment(self->obj));
}

static PyObject* Py_LLVMValue_SetAlignment(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	LLVMSetAlignment(self->obj, arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetNextGlobal(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetNextGlobal(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetPreviousGlobal(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetPreviousGlobal(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_DeleteGlobal(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	LLVMDeleteGlobal(self->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetInitializer(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetInitializer(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_SetInitializer(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMValue_Type, &arg0))
	{
		return nullptr;
	}

	LLVMSetInitializer(self->obj, arg0->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_IsThreadLocal(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyBool_FromLong(LLVMIsThreadLocal(self->obj));
}

static PyObject* Py_LLVMValue_SetThreadLocal(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	PyObject* arg0;
	if (!PyArg_ParseTuple(args, "O!", &PyBool_Type, &arg0))
	{
		return nullptr;
	}

	LLVMBool carg0 = PyObject_IsTrue(arg0);
	LLVMSetThreadLocal(self->obj, carg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_IsGlobalConstant(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyBool_FromLong(LLVMIsGlobalConstant(self->obj));
}

static PyObject* Py_LLVMValue_SetGlobalConstant(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	PyObject* arg0;
	if (!PyArg_ParseTuple(args, "O!", &PyBool_Type, &arg0))
	{
		return nullptr;
	}

	LLVMBool carg0 = PyObject_IsTrue(arg0);
	LLVMSetGlobalConstant(self->obj, carg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetThreadLocalMode(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMGetThreadLocalMode(self->obj));
}

static PyObject* Py_LLVMValue_SetThreadLocalMode(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	LLVMSetThreadLocalMode(self->obj, (LLVMThreadLocalMode)arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_IsExternallyInitialized(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyBool_FromLong(LLVMIsExternallyInitialized(self->obj));
}

static PyObject* Py_LLVMValue_SetExternallyInitialized(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	PyObject* arg0;
	if (!PyArg_ParseTuple(args, "O!", &PyBool_Type, &arg0))
	{
		return nullptr;
	}

	LLVMBool carg0 = PyObject_IsTrue(arg0);
	LLVMSetExternallyInitialized(self->obj, carg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_DeleteFunction(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	LLVMDeleteFunction(self->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetPersonalityFn(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetPersonalityFn(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_SetPersonalityFn(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMValue_Type, &arg0))
	{
		return nullptr;
	}

	LLVMSetPersonalityFn(self->obj, arg0->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetIntrinsicID(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMGetIntrinsicID(self->obj));
}

static PyObject* Py_LLVMValue_GetFunctionCallConv(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMGetFunctionCallConv(self->obj));
}

static PyObject* Py_LLVMValue_SetFunctionCallConv(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	LLVMSetFunctionCallConv(self->obj, arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetGC(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyString_FromString(LLVMGetGC(self->obj));
}

static PyObject* Py_LLVMValue_SetGC(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	const char* arg0;
	if (!PyArg_ParseTuple(args, "s", &arg0))
	{
		return nullptr;
	}

	LLVMSetGC(self->obj, arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_AddFunctionAttr(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	LLVMAddFunctionAttr(self->obj, (LLVMAttribute)arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_AddTargetDependentFunctionAttr(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	const char* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "ss", &arg0, &arg1))
	{
		return nullptr;
	}

	LLVMAddTargetDependentFunctionAttr(self->obj, arg0, arg1);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetFunctionAttr(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMGetFunctionAttr(self->obj));
}

static PyObject* Py_LLVMValue_RemoveFunctionAttr(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	LLVMRemoveFunctionAttr(self->obj, (LLVMAttribute)arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_CountParams(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMCountParams(self->obj));
}

static PyObject* Py_LLVMValue_GetParam(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMGetParam(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetParamParent(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetParamParent(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetFirstParam(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetFirstParam(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetLastParam(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetLastParam(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetNextParam(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetNextParam(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetPreviousParam(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetPreviousParam(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_AddAttribute(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	LLVMAddAttribute(self->obj, (LLVMAttribute)arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_RemoveAttribute(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	LLVMRemoveAttribute(self->obj, (LLVMAttribute)arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetAttribute(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMGetAttribute(self->obj));
}

static PyObject* Py_LLVMValue_SetParamAlignment(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	LLVMSetParamAlignment(self->obj, arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetMDNodeNumOperands(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMGetMDNodeNumOperands(self->obj));
}

static PyObject* Py_LLVMValue_ValueIsBasicBlock(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyBool_FromLong(LLVMValueIsBasicBlock(self->obj));
}

static PyObject* Py_LLVMValue_ValueAsBasicBlock(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMValueAsBasicBlock(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* result = (Py_LLVM_Wrapped<LLVMBasicBlockRef>*)PyType_GenericNew(&Py_LLVMBasicBlock_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_CountBasicBlocks(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMCountBasicBlocks(self->obj));
}

static PyObject* Py_LLVMValue_GetFirstBasicBlock(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetFirstBasicBlock(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* result = (Py_LLVM_Wrapped<LLVMBasicBlockRef>*)PyType_GenericNew(&Py_LLVMBasicBlock_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetLastBasicBlock(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetLastBasicBlock(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* result = (Py_LLVM_Wrapped<LLVMBasicBlockRef>*)PyType_GenericNew(&Py_LLVMBasicBlock_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetEntryBasicBlock(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetEntryBasicBlock(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* result = (Py_LLVM_Wrapped<LLVMBasicBlockRef>*)PyType_GenericNew(&Py_LLVMBasicBlock_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_AppendBasicBlock(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	const char* arg0;
	if (!PyArg_ParseTuple(args, "s", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMAppendBasicBlock(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* result = (Py_LLVM_Wrapped<LLVMBasicBlockRef>*)PyType_GenericNew(&Py_LLVMBasicBlock_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetMetadata(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMGetMetadata(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_SetMetadata(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	if (!PyArg_ParseTuple(args, "LO!", &arg0, &Py_LLVMValue_Type, &arg1))
	{
		return nullptr;
	}

	LLVMSetMetadata(self->obj, arg0, arg1->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetInstructionParent(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetInstructionParent(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* result = (Py_LLVM_Wrapped<LLVMBasicBlockRef>*)PyType_GenericNew(&Py_LLVMBasicBlock_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetNextInstruction(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetNextInstruction(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetPreviousInstruction(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetPreviousInstruction(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_InstructionEraseFromParent(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	LLVMInstructionEraseFromParent(self->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetInstructionOpcode(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMGetInstructionOpcode(self->obj));
}

static PyObject* Py_LLVMValue_GetICmpPredicate(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMGetICmpPredicate(self->obj));
}

static PyObject* Py_LLVMValue_GetFCmpPredicate(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMGetFCmpPredicate(self->obj));
}

static PyObject* Py_LLVMValue_InstructionClone(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMInstructionClone(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_SetInstructionCallConv(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	LLVMSetInstructionCallConv(self->obj, arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetInstructionCallConv(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMGetInstructionCallConv(self->obj));
}

static PyObject* Py_LLVMValue_AddInstrAttribute(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	long long arg1;
	if (!PyArg_ParseTuple(args, "LL", &arg0, &arg1))
	{
		return nullptr;
	}

	LLVMAddInstrAttribute(self->obj, arg0, (LLVMAttribute)arg1);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_RemoveInstrAttribute(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	long long arg1;
	if (!PyArg_ParseTuple(args, "LL", &arg0, &arg1))
	{
		return nullptr;
	}

	LLVMRemoveInstrAttribute(self->obj, arg0, (LLVMAttribute)arg1);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_SetInstrParamAlignment(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	long long arg1;
	if (!PyArg_ParseTuple(args, "LL", &arg0, &arg1))
	{
		return nullptr;
	}

	LLVMSetInstrParamAlignment(self->obj, arg0, arg1);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_IsTailCall(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyBool_FromLong(LLVMIsTailCall(self->obj));
}

static PyObject* Py_LLVMValue_SetTailCall(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	PyObject* arg0;
	if (!PyArg_ParseTuple(args, "O!", &PyBool_Type, &arg0))
	{
		return nullptr;
	}

	LLVMBool carg0 = PyObject_IsTrue(arg0);
	LLVMSetTailCall(self->obj, carg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetNumSuccessors(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMGetNumSuccessors(self->obj));
}

static PyObject* Py_LLVMValue_GetSuccessor(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMGetSuccessor(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* result = (Py_LLVM_Wrapped<LLVMBasicBlockRef>*)PyType_GenericNew(&Py_LLVMBasicBlock_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_SetSuccessor(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* arg1;
	if (!PyArg_ParseTuple(args, "LO!", &arg0, &Py_LLVMBasicBlock_Type, &arg1))
	{
		return nullptr;
	}

	LLVMSetSuccessor(self->obj, arg0, arg1->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_IsConditional(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyBool_FromLong(LLVMIsConditional(self->obj));
}

static PyObject* Py_LLVMValue_GetCondition(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetCondition(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_SetCondition(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMValue_Type, &arg0))
	{
		return nullptr;
	}

	LLVMSetCondition(self->obj, arg0->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetSwitchDefaultDest(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	auto callReturn = LLVMGetSwitchDefaultDest(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* result = (Py_LLVM_Wrapped<LLVMBasicBlockRef>*)PyType_GenericNew(&Py_LLVMBasicBlock_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_CountIncoming(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyInt_FromLong(LLVMCountIncoming(self->obj));
}

static PyObject* Py_LLVMValue_GetIncomingValue(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMGetIncomingValue(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_GetIncomingBlock(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMGetIncomingBlock(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* result = (Py_LLVM_Wrapped<LLVMBasicBlockRef>*)PyType_GenericNew(&Py_LLVMBasicBlock_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMValue_AddCase(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* arg1;
	if (!PyArg_ParseTuple(args, "O!O!", &Py_LLVMValue_Type, &arg0, &Py_LLVMBasicBlock_Type, &arg1))
	{
		return nullptr;
	}

	LLVMAddCase(self->obj, arg0->obj, arg1->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_AddDestination(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMBasicBlock_Type, &arg0))
	{
		return nullptr;
	}

	LLVMAddDestination(self->obj, arg0->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_AddClause(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMValue_Type, &arg0))
	{
		return nullptr;
	}

	LLVMAddClause(self->obj, arg0->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_SetCleanup(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	PyObject* arg0;
	if (!PyArg_ParseTuple(args, "O!", &PyBool_Type, &arg0))
	{
		return nullptr;
	}

	LLVMBool carg0 = PyObject_IsTrue(arg0);
	LLVMSetCleanup(self->obj, carg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMValue_GetVolatile(Py_LLVM_Wrapped<LLVMValueRef>* self)
{
	return PyBool_FromLong(LLVMGetVolatile(self->obj));
}

static PyObject* Py_LLVMValue_SetVolatile(Py_LLVM_Wrapped<LLVMValueRef>* self, PyObject* args)
{
	PyObject* arg0;
	if (!PyArg_ParseTuple(args, "O!", &PyBool_Type, &arg0))
	{
		return nullptr;
	}

	LLVMBool carg0 = PyObject_IsTrue(arg0);
	LLVMSetVolatile(self->obj, carg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMPassRegistry_InitializeCore(Py_LLVM_Wrapped<LLVMPassRegistryRef>* self)
{
	LLVMInitializeCore(self->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMPassManager_RunPassManager(Py_LLVM_Wrapped<LLVMPassManagerRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMModuleRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMModule_Type, &arg0))
	{
		return nullptr;
	}

	return PyBool_FromLong(LLVMRunPassManager(self->obj, arg0->obj));
}

static PyObject* Py_LLVMPassManager_InitializeFunctionPassManager(Py_LLVM_Wrapped<LLVMPassManagerRef>* self)
{
	return PyBool_FromLong(LLVMInitializeFunctionPassManager(self->obj));
}

static PyObject* Py_LLVMPassManager_RunFunctionPassManager(Py_LLVM_Wrapped<LLVMPassManagerRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMValue_Type, &arg0))
	{
		return nullptr;
	}

	return PyBool_FromLong(LLVMRunFunctionPassManager(self->obj, arg0->obj));
}

static PyObject* Py_LLVMPassManager_FinalizeFunctionPassManager(Py_LLVM_Wrapped<LLVMPassManagerRef>* self)
{
	return PyBool_FromLong(LLVMFinalizeFunctionPassManager(self->obj));
}

static PyObject* Py_LLVMPassManager_DisposePassManager(Py_LLVM_Wrapped<LLVMPassManagerRef>* self)
{
	LLVMDisposePassManager(self->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMModule_CloneModule(Py_LLVM_Wrapped<LLVMModuleRef>* self)
{
	auto callReturn = LLVMCloneModule(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMModuleRef>* result = (Py_LLVM_Wrapped<LLVMModuleRef>*)PyType_GenericNew(&Py_LLVMModule_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMModule_DisposeModule(Py_LLVM_Wrapped<LLVMModuleRef>* self)
{
	LLVMDisposeModule(self->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMModule_GetDataLayout(Py_LLVM_Wrapped<LLVMModuleRef>* self)
{
	return PyString_FromString(LLVMGetDataLayout(self->obj));
}

static PyObject* Py_LLVMModule_SetDataLayout(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args)
{
	const char* arg0;
	if (!PyArg_ParseTuple(args, "s", &arg0))
	{
		return nullptr;
	}

	LLVMSetDataLayout(self->obj, arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMModule_GetTarget(Py_LLVM_Wrapped<LLVMModuleRef>* self)
{
	return PyString_FromString(LLVMGetTarget(self->obj));
}

static PyObject* Py_LLVMModule_SetTarget(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args)
{
	const char* arg0;
	if (!PyArg_ParseTuple(args, "s", &arg0))
	{
		return nullptr;
	}

	LLVMSetTarget(self->obj, arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMModule_DumpModule(Py_LLVM_Wrapped<LLVMModuleRef>* self)
{
	LLVMDumpModule(self->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMModule_SetModuleInlineAsm(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args)
{
	const char* arg0;
	if (!PyArg_ParseTuple(args, "s", &arg0))
	{
		return nullptr;
	}

	LLVMSetModuleInlineAsm(self->obj, arg0);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMModule_GetModuleContext(Py_LLVM_Wrapped<LLVMModuleRef>* self)
{
	auto callReturn = LLVMGetModuleContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMContextRef>* result = (Py_LLVM_Wrapped<LLVMContextRef>*)PyType_GenericNew(&Py_LLVMContext_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMModule_GetTypeByName(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args)
{
	const char* arg0;
	if (!PyArg_ParseTuple(args, "s", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMGetTypeByName(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMModule_GetNamedMetadataNumOperands(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args)
{
	const char* arg0;
	if (!PyArg_ParseTuple(args, "s", &arg0))
	{
		return nullptr;
	}

	return PyInt_FromLong(LLVMGetNamedMetadataNumOperands(self->obj, arg0));
}

static PyObject* Py_LLVMModule_AddNamedMetadataOperand(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args)
{
	const char* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	if (!PyArg_ParseTuple(args, "sO!", &arg0, &Py_LLVMValue_Type, &arg1))
	{
		return nullptr;
	}

	LLVMAddNamedMetadataOperand(self->obj, arg0, arg1->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMModule_AddFunction(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args)
{
	const char* arg0;
	Py_LLVM_Wrapped<LLVMTypeRef>* arg1;
	if (!PyArg_ParseTuple(args, "sO!", &arg0, &Py_LLVMType_Type, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMAddFunction(self->obj, arg0, arg1->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMModule_GetNamedFunction(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args)
{
	const char* arg0;
	if (!PyArg_ParseTuple(args, "s", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMGetNamedFunction(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMModule_GetFirstFunction(Py_LLVM_Wrapped<LLVMModuleRef>* self)
{
	auto callReturn = LLVMGetFirstFunction(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMModule_GetLastFunction(Py_LLVM_Wrapped<LLVMModuleRef>* self)
{
	auto callReturn = LLVMGetLastFunction(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMModule_AddGlobal(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMTypeRef>* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "O!s", &Py_LLVMType_Type, &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMAddGlobal(self->obj, arg0->obj, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMModule_AddGlobalInAddressSpace(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMTypeRef>* arg0;
	const char* arg1;
	long long arg2;
	if (!PyArg_ParseTuple(args, "O!sL", &Py_LLVMType_Type, &arg0, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMAddGlobalInAddressSpace(self->obj, arg0->obj, arg1, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMModule_GetNamedGlobal(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args)
{
	const char* arg0;
	if (!PyArg_ParseTuple(args, "s", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMGetNamedGlobal(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMModule_GetFirstGlobal(Py_LLVM_Wrapped<LLVMModuleRef>* self)
{
	auto callReturn = LLVMGetFirstGlobal(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMModule_GetLastGlobal(Py_LLVM_Wrapped<LLVMModuleRef>* self)
{
	auto callReturn = LLVMGetLastGlobal(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMModule_AddAlias(Py_LLVM_Wrapped<LLVMModuleRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMTypeRef>* arg0;
	Py_LLVM_Wrapped<LLVMValueRef>* arg1;
	const char* arg2;
	if (!PyArg_ParseTuple(args, "O!O!s", &Py_LLVMType_Type, &arg0, &Py_LLVMValue_Type, &arg1, &arg2))
	{
		return nullptr;
	}

	auto callReturn = LLVMAddAlias(self->obj, arg0->obj, arg1->obj, arg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMModule_CreateModuleProviderForExistingModule(Py_LLVM_Wrapped<LLVMModuleRef>* self)
{
	auto callReturn = LLVMCreateModuleProviderForExistingModule(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMModuleProviderRef>* result = (Py_LLVM_Wrapped<LLVMModuleProviderRef>*)PyType_GenericNew(&Py_LLVMModuleProvider_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMModule_CreateFunctionPassManagerForModule(Py_LLVM_Wrapped<LLVMModuleRef>* self)
{
	auto callReturn = LLVMCreateFunctionPassManagerForModule(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMPassManagerRef>* result = (Py_LLVM_Wrapped<LLVMPassManagerRef>*)PyType_GenericNew(&Py_LLVMPassManager_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_ContextDispose(Py_LLVM_Wrapped<LLVMContextRef>* self)
{
	LLVMContextDispose(self->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMContext_GetMDKindID(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args)
{
	const char* arg0;
	long long arg1;
	if (!PyArg_ParseTuple(args, "sL", &arg0, &arg1))
	{
		return nullptr;
	}

	return PyInt_FromLong(LLVMGetMDKindIDInContext(self->obj, arg0, arg1));
}

static PyObject* Py_LLVMContext_Int1Type(Py_LLVM_Wrapped<LLVMContextRef>* self)
{
	auto callReturn = LLVMInt1TypeInContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_Int8Type(Py_LLVM_Wrapped<LLVMContextRef>* self)
{
	auto callReturn = LLVMInt8TypeInContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_Int16Type(Py_LLVM_Wrapped<LLVMContextRef>* self)
{
	auto callReturn = LLVMInt16TypeInContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_Int32Type(Py_LLVM_Wrapped<LLVMContextRef>* self)
{
	auto callReturn = LLVMInt32TypeInContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_Int64Type(Py_LLVM_Wrapped<LLVMContextRef>* self)
{
	auto callReturn = LLVMInt64TypeInContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_IntType(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMIntTypeInContext(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_HalfType(Py_LLVM_Wrapped<LLVMContextRef>* self)
{
	auto callReturn = LLVMHalfTypeInContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_FloatType(Py_LLVM_Wrapped<LLVMContextRef>* self)
{
	auto callReturn = LLVMFloatTypeInContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_DoubleType(Py_LLVM_Wrapped<LLVMContextRef>* self)
{
	auto callReturn = LLVMDoubleTypeInContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_X86FP80Type(Py_LLVM_Wrapped<LLVMContextRef>* self)
{
	auto callReturn = LLVMX86FP80TypeInContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_FP128Type(Py_LLVM_Wrapped<LLVMContextRef>* self)
{
	auto callReturn = LLVMFP128TypeInContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_PPCFP128Type(Py_LLVM_Wrapped<LLVMContextRef>* self)
{
	auto callReturn = LLVMPPCFP128TypeInContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_StructType(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args)
{
	PyObject* arg0;
	PyObject* arg1;
	if (!PyArg_ParseTuple(args, "OO!", &arg0, &PyBool_Type, &arg1))
	{
		return nullptr;
	}

	auto seq0 = TAKEREF PySequence_Fast(arg0, "argument 1 expected to be a sequence");
	if (!seq0)
	{
		return nullptr;
	}
	Py_ssize_t len0 = PySequence_Size(seq0.get());
	std::unique_ptr<LLVMTypeRef[]> array0(new LLVMTypeRef[len0]);
	for (Py_ssize_t i = 0; i < len0; ++i)
	{
		auto wrapped = (Py_LLVM_Wrapped<LLVMTypeRef>*)PySequence_Fast_GET_ITEM(seq0.get(), i);
		array0[i] = wrapped->obj;
	}
	LLVMBool carg1 = PyObject_IsTrue(arg1);
	auto callReturn = LLVMStructTypeInContext(self->obj, array0.get(), len0, carg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_StructCreateNamed(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args)
{
	const char* arg0;
	if (!PyArg_ParseTuple(args, "s", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMStructCreateNamed(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_VoidType(Py_LLVM_Wrapped<LLVMContextRef>* self)
{
	auto callReturn = LLVMVoidTypeInContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_LabelType(Py_LLVM_Wrapped<LLVMContextRef>* self)
{
	auto callReturn = LLVMLabelTypeInContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_X86MMXType(Py_LLVM_Wrapped<LLVMContextRef>* self)
{
	auto callReturn = LLVMX86MMXTypeInContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_ConstString(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args)
{
	const char* arg0;
	long long arg1;
	PyObject* arg2;
	if (!PyArg_ParseTuple(args, "sLO!", &arg0, &arg1, &PyBool_Type, &arg2))
	{
		return nullptr;
	}

	LLVMBool carg2 = PyObject_IsTrue(arg2);
	auto callReturn = LLVMConstStringInContext(self->obj, arg0, arg1, carg2);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_ConstStruct(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args)
{
	PyObject* arg0;
	PyObject* arg1;
	if (!PyArg_ParseTuple(args, "OO!", &arg0, &PyBool_Type, &arg1))
	{
		return nullptr;
	}

	auto seq0 = TAKEREF PySequence_Fast(arg0, "argument 1 expected to be a sequence");
	if (!seq0)
	{
		return nullptr;
	}
	Py_ssize_t len0 = PySequence_Size(seq0.get());
	std::unique_ptr<LLVMValueRef[]> array0(new LLVMValueRef[len0]);
	for (Py_ssize_t i = 0; i < len0; ++i)
	{
		auto wrapped = (Py_LLVM_Wrapped<LLVMValueRef>*)PySequence_Fast_GET_ITEM(seq0.get(), i);
		array0[i] = wrapped->obj;
	}
	LLVMBool carg1 = PyObject_IsTrue(arg1);
	auto callReturn = LLVMConstStructInContext(self->obj, array0.get(), len0, carg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_MDString(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args)
{
	const char* arg0;
	long long arg1;
	if (!PyArg_ParseTuple(args, "sL", &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMMDStringInContext(self->obj, arg0, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_MDNode(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args)
{
	PyObject* arg0;
	if (!PyArg_ParseTuple(args, "O", &arg0))
	{
		return nullptr;
	}

	auto seq0 = TAKEREF PySequence_Fast(arg0, "argument 1 expected to be a sequence");
	if (!seq0)
	{
		return nullptr;
	}
	Py_ssize_t len0 = PySequence_Size(seq0.get());
	std::unique_ptr<LLVMValueRef[]> array0(new LLVMValueRef[len0]);
	for (Py_ssize_t i = 0; i < len0; ++i)
	{
		auto wrapped = (Py_LLVM_Wrapped<LLVMValueRef>*)PySequence_Fast_GET_ITEM(seq0.get(), i);
		array0[i] = wrapped->obj;
	}
	auto callReturn = LLVMMDNodeInContext(self->obj, array0.get(), len0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_AppendBasicBlock(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMValueRef>* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "O!s", &Py_LLVMValue_Type, &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMAppendBasicBlockInContext(self->obj, arg0->obj, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* result = (Py_LLVM_Wrapped<LLVMBasicBlockRef>*)PyType_GenericNew(&Py_LLVMBasicBlock_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_InsertBasicBlock(Py_LLVM_Wrapped<LLVMContextRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* arg0;
	const char* arg1;
	if (!PyArg_ParseTuple(args, "O!s", &Py_LLVMBasicBlock_Type, &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMInsertBasicBlockInContext(self->obj, arg0->obj, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* result = (Py_LLVM_Wrapped<LLVMBasicBlockRef>*)PyType_GenericNew(&Py_LLVMBasicBlock_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMContext_CreateBuilder(Py_LLVM_Wrapped<LLVMContextRef>* self)
{
	auto callReturn = LLVMCreateBuilderInContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMBuilderRef>* result = (Py_LLVM_Wrapped<LLVMBuilderRef>*)PyType_GenericNew(&Py_LLVMBuilder_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMDiagnosticInfo_GetDiagInfoSeverity(Py_LLVM_Wrapped<LLVMDiagnosticInfoRef>* self)
{
	return PyInt_FromLong(LLVMGetDiagInfoSeverity(self->obj));
}

static PyObject* Py_LLVMBasicBlock_BasicBlockAsValue(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self)
{
	auto callReturn = LLVMBasicBlockAsValue(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBasicBlock_GetBasicBlockParent(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self)
{
	auto callReturn = LLVMGetBasicBlockParent(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBasicBlock_GetBasicBlockTerminator(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self)
{
	auto callReturn = LLVMGetBasicBlockTerminator(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBasicBlock_GetNextBasicBlock(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self)
{
	auto callReturn = LLVMGetNextBasicBlock(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* result = (Py_LLVM_Wrapped<LLVMBasicBlockRef>*)PyType_GenericNew(&Py_LLVMBasicBlock_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBasicBlock_GetPreviousBasicBlock(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self)
{
	auto callReturn = LLVMGetPreviousBasicBlock(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* result = (Py_LLVM_Wrapped<LLVMBasicBlockRef>*)PyType_GenericNew(&Py_LLVMBasicBlock_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBasicBlock_InsertBasicBlock(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self, PyObject* args)
{
	const char* arg0;
	if (!PyArg_ParseTuple(args, "s", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMInsertBasicBlock(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* result = (Py_LLVM_Wrapped<LLVMBasicBlockRef>*)PyType_GenericNew(&Py_LLVMBasicBlock_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBasicBlock_DeleteBasicBlock(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self)
{
	LLVMDeleteBasicBlock(self->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMBasicBlock_RemoveBasicBlockFromParent(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self)
{
	LLVMRemoveBasicBlockFromParent(self->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMBasicBlock_MoveBasicBlockBefore(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMBasicBlock_Type, &arg0))
	{
		return nullptr;
	}

	LLVMMoveBasicBlockBefore(self->obj, arg0->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMBasicBlock_MoveBasicBlockAfter(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self, PyObject* args)
{
	Py_LLVM_Wrapped<LLVMBasicBlockRef>* arg0;
	if (!PyArg_ParseTuple(args, "O!", &Py_LLVMBasicBlock_Type, &arg0))
	{
		return nullptr;
	}

	LLVMMoveBasicBlockAfter(self->obj, arg0->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMBasicBlock_GetFirstInstruction(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self)
{
	auto callReturn = LLVMGetFirstInstruction(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMBasicBlock_GetLastInstruction(Py_LLVM_Wrapped<LLVMBasicBlockRef>* self)
{
	auto callReturn = LLVMGetLastInstruction(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_GetTypeKind(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	return PyInt_FromLong(LLVMGetTypeKind(self->obj));
}

static PyObject* Py_LLVMType_TypeIsSized(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	return PyBool_FromLong(LLVMTypeIsSized(self->obj));
}

static PyObject* Py_LLVMType_GetTypeContext(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	auto callReturn = LLVMGetTypeContext(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMContextRef>* result = (Py_LLVM_Wrapped<LLVMContextRef>*)PyType_GenericNew(&Py_LLVMContext_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_DumpType(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	LLVMDumpType(self->obj);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMType_GetIntTypeWidth(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	return PyInt_FromLong(LLVMGetIntTypeWidth(self->obj));
}

static PyObject* Py_LLVMType_FunctionType(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args)
{
	PyObject* arg0;
	PyObject* arg1;
	if (!PyArg_ParseTuple(args, "OO!", &arg0, &PyBool_Type, &arg1))
	{
		return nullptr;
	}

	auto seq0 = TAKEREF PySequence_Fast(arg0, "argument 1 expected to be a sequence");
	if (!seq0)
	{
		return nullptr;
	}
	Py_ssize_t len0 = PySequence_Size(seq0.get());
	std::unique_ptr<LLVMTypeRef[]> array0(new LLVMTypeRef[len0]);
	for (Py_ssize_t i = 0; i < len0; ++i)
	{
		auto wrapped = (Py_LLVM_Wrapped<LLVMTypeRef>*)PySequence_Fast_GET_ITEM(seq0.get(), i);
		array0[i] = wrapped->obj;
	}
	LLVMBool carg1 = PyObject_IsTrue(arg1);
	auto callReturn = LLVMFunctionType(self->obj, array0.get(), len0, carg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_IsFunctionVarArg(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	return PyBool_FromLong(LLVMIsFunctionVarArg(self->obj));
}

static PyObject* Py_LLVMType_GetReturnType(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	auto callReturn = LLVMGetReturnType(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_CountParamTypes(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	return PyInt_FromLong(LLVMCountParamTypes(self->obj));
}

static PyObject* Py_LLVMType_GetStructName(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	return PyString_FromString(LLVMGetStructName(self->obj));
}

static PyObject* Py_LLVMType_StructSetBody(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args)
{
	PyObject* arg0;
	PyObject* arg1;
	if (!PyArg_ParseTuple(args, "OO!", &arg0, &PyBool_Type, &arg1))
	{
		return nullptr;
	}

	auto seq0 = TAKEREF PySequence_Fast(arg0, "argument 1 expected to be a sequence");
	if (!seq0)
	{
		return nullptr;
	}
	Py_ssize_t len0 = PySequence_Size(seq0.get());
	std::unique_ptr<LLVMTypeRef[]> array0(new LLVMTypeRef[len0]);
	for (Py_ssize_t i = 0; i < len0; ++i)
	{
		auto wrapped = (Py_LLVM_Wrapped<LLVMTypeRef>*)PySequence_Fast_GET_ITEM(seq0.get(), i);
		array0[i] = wrapped->obj;
	}
	LLVMBool carg1 = PyObject_IsTrue(arg1);
	LLVMStructSetBody(self->obj, array0.get(), len0, carg1);
	Py_RETURN_NONE;
}

static PyObject* Py_LLVMType_CountStructElementTypes(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	return PyInt_FromLong(LLVMCountStructElementTypes(self->obj));
}

static PyObject* Py_LLVMType_StructGetTypeAtIndex(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMStructGetTypeAtIndex(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_IsPackedStruct(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	return PyBool_FromLong(LLVMIsPackedStruct(self->obj));
}

static PyObject* Py_LLVMType_IsOpaqueStruct(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	return PyBool_FromLong(LLVMIsOpaqueStruct(self->obj));
}

static PyObject* Py_LLVMType_GetElementType(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	auto callReturn = LLVMGetElementType(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_ArrayType(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMArrayType(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_GetArrayLength(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	return PyInt_FromLong(LLVMGetArrayLength(self->obj));
}

static PyObject* Py_LLVMType_PointerType(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMPointerType(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_GetPointerAddressSpace(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	return PyInt_FromLong(LLVMGetPointerAddressSpace(self->obj));
}

static PyObject* Py_LLVMType_VectorType(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args)
{
	long long arg0;
	if (!PyArg_ParseTuple(args, "L", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMVectorType(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMTypeRef>* result = (Py_LLVM_Wrapped<LLVMTypeRef>*)PyType_GenericNew(&Py_LLVMType_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_GetVectorSize(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	return PyInt_FromLong(LLVMGetVectorSize(self->obj));
}

static PyObject* Py_LLVMType_ConstNull(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	auto callReturn = LLVMConstNull(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_ConstAllOnes(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	auto callReturn = LLVMConstAllOnes(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_GetUndef(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	auto callReturn = LLVMGetUndef(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_ConstPointerNull(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	auto callReturn = LLVMConstPointerNull(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_ConstRealOfString(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args)
{
	const char* arg0;
	if (!PyArg_ParseTuple(args, "s", &arg0))
	{
		return nullptr;
	}

	auto callReturn = LLVMConstRealOfString(self->obj, arg0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_ConstRealOfStringAndSize(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args)
{
	const char* arg0;
	long long arg1;
	if (!PyArg_ParseTuple(args, "sL", &arg0, &arg1))
	{
		return nullptr;
	}

	auto callReturn = LLVMConstRealOfStringAndSize(self->obj, arg0, arg1);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_ConstArray(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args)
{
	PyObject* arg0;
	if (!PyArg_ParseTuple(args, "O", &arg0))
	{
		return nullptr;
	}

	auto seq0 = TAKEREF PySequence_Fast(arg0, "argument 1 expected to be a sequence");
	if (!seq0)
	{
		return nullptr;
	}
	Py_ssize_t len0 = PySequence_Size(seq0.get());
	std::unique_ptr<LLVMValueRef[]> array0(new LLVMValueRef[len0]);
	for (Py_ssize_t i = 0; i < len0; ++i)
	{
		auto wrapped = (Py_LLVM_Wrapped<LLVMValueRef>*)PySequence_Fast_GET_ITEM(seq0.get(), i);
		array0[i] = wrapped->obj;
	}
	auto callReturn = LLVMConstArray(self->obj, array0.get(), len0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_ConstNamedStruct(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args)
{
	PyObject* arg0;
	if (!PyArg_ParseTuple(args, "O", &arg0))
	{
		return nullptr;
	}

	auto seq0 = TAKEREF PySequence_Fast(arg0, "argument 1 expected to be a sequence");
	if (!seq0)
	{
		return nullptr;
	}
	Py_ssize_t len0 = PySequence_Size(seq0.get());
	std::unique_ptr<LLVMValueRef[]> array0(new LLVMValueRef[len0]);
	for (Py_ssize_t i = 0; i < len0; ++i)
	{
		auto wrapped = (Py_LLVM_Wrapped<LLVMValueRef>*)PySequence_Fast_GET_ITEM(seq0.get(), i);
		array0[i] = wrapped->obj;
	}
	auto callReturn = LLVMConstNamedStruct(self->obj, array0.get(), len0);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_AlignOf(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	auto callReturn = LLVMAlignOf(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_SizeOf(Py_LLVM_Wrapped<LLVMTypeRef>* self)
{
	auto callReturn = LLVMSizeOf(self->obj);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}

static PyObject* Py_LLVMType_ConstInlineAsm(Py_LLVM_Wrapped<LLVMTypeRef>* self, PyObject* args)
{
	const char* arg0;
	const char* arg1;
	PyObject* arg2;
	PyObject* arg3;
	if (!PyArg_ParseTuple(args, "ssO!O!", &arg0, &arg1, &PyBool_Type, &arg2, &PyBool_Type, &arg3))
	{
		return nullptr;
	}

	LLVMBool carg2 = PyObject_IsTrue(arg2);
	LLVMBool carg3 = PyObject_IsTrue(arg3);
	auto callReturn = LLVMConstInlineAsm(self->obj, arg0, arg1, carg2, carg3);
	if (callReturn == nullptr)
	{
		Py_RETURN_NONE;
	}
	Py_LLVM_Wrapped<LLVMValueRef>* result = (Py_LLVM_Wrapped<LLVMValueRef>*)PyType_GenericNew(&Py_LLVMValue_Type, nullptr, nullptr);
	result->obj = callReturn;
	return (PyObject*)result;
}


PyMODINIT_FUNC initLlvmModule(PyObject** module)
{
	if (PyType_Ready(&Py_LLVMUse_Type) < 0) return;
	if (PyType_Ready(&Py_LLVMModuleProvider_Type) < 0) return;
	if (PyType_Ready(&Py_LLVMBuilder_Type) < 0) return;
	if (PyType_Ready(&Py_LLVMValue_Type) < 0) return;
	if (PyType_Ready(&Py_LLVMPassRegistry_Type) < 0) return;
	if (PyType_Ready(&Py_LLVMPassManager_Type) < 0) return;
	if (PyType_Ready(&Py_LLVMModule_Type) < 0) return;
	if (PyType_Ready(&Py_LLVMContext_Type) < 0) return;
	if (PyType_Ready(&Py_LLVMDiagnosticInfo_Type) < 0) return;
	if (PyType_Ready(&Py_LLVMBasicBlock_Type) < 0) return;
	if (PyType_Ready(&Py_LLVMType_Type) < 0) return;

	*module = Py_InitModule("llvm", nullptr);
	Py_INCREF(&Py_LLVMUse_Type);
	Py_INCREF(&Py_LLVMModuleProvider_Type);
	Py_INCREF(&Py_LLVMBuilder_Type);
	Py_INCREF(&Py_LLVMValue_Type);
	Py_INCREF(&Py_LLVMPassRegistry_Type);
	Py_INCREF(&Py_LLVMPassManager_Type);
	Py_INCREF(&Py_LLVMModule_Type);
	Py_INCREF(&Py_LLVMContext_Type);
	Py_INCREF(&Py_LLVMDiagnosticInfo_Type);
	Py_INCREF(&Py_LLVMBasicBlock_Type);
	Py_INCREF(&Py_LLVMType_Type);
	PyModule_AddObject(*module, "Use", (PyObject*)&Py_LLVMUse_Type);
	PyModule_AddObject(*module, "ModuleProvider", (PyObject*)&Py_LLVMModuleProvider_Type);
	PyModule_AddObject(*module, "Builder", (PyObject*)&Py_LLVMBuilder_Type);
	PyModule_AddObject(*module, "Value", (PyObject*)&Py_LLVMValue_Type);
	PyModule_AddObject(*module, "PassRegistry", (PyObject*)&Py_LLVMPassRegistry_Type);
	PyModule_AddObject(*module, "PassManager", (PyObject*)&Py_LLVMPassManager_Type);
	PyModule_AddObject(*module, "Module", (PyObject*)&Py_LLVMModule_Type);
	PyModule_AddObject(*module, "Context", (PyObject*)&Py_LLVMContext_Type);
	PyModule_AddObject(*module, "DiagnosticInfo", (PyObject*)&Py_LLVMDiagnosticInfo_Type);
	PyModule_AddObject(*module, "BasicBlock", (PyObject*)&Py_LLVMBasicBlock_Type);
	PyModule_AddObject(*module, "Type", (PyObject*)&Py_LLVMType_Type);
}

#pragma clang diagnostic pop
