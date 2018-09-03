# -*- coding: UTF-8 -*-

#
# bindings.py
# Copyright (C) 2015 Félix Cloutier.
# All Rights Reserved.
#
# This file is distributed under the University of Illinois Open Source
# license. See LICENSE.md for details.
#

#
# (I'm a Python 2 script)
# (feed me a preprocessed llvm-c/Core.h in stdin)
#

from __future__ import print_function
import re
import os
import string
import sys

if len(sys.argv) != 1:
	sys.stderr.write("usage: %s < preprocessed-header-file" % sys.argv[0])
	sys.exit(1)

llvmTypeRE = re.compile("LLVM(.+)Ref")

class CParameter(object):
	@staticmethod
	def parse(paramString):
		wordCharset = string.ascii_letters + string.digits
		result = []
		for param in paramString.split(","):
			param = param.strip()
			nameStart = None
			for i in range(len(param)):
				char = param[i]
				if char not in wordCharset:
					nameStart = i + 1
			
			type, name = (param[:nameStart], param[nameStart:]) if nameStart != None else (param, "")
			p = CParameter(type, name)
			result.append(p)
		
		if len(result) == 1 and result[0].type == "void":
			result = []
		return result
	
	def __init__(self, type, name):
		if type[-1] == ',':
			type = type[:-1]
		self.type = type.strip()
		self.name = name.strip()
	
	def getRefType(self):
		match = llvmTypeRE.match(self.type)
		if match == None:
			return None
		return match.group(1)
	
	def isDoublePointer(self):
		indirections = 0
		type = self.type
		while type[-1] == '*':
			indirections += 1
			type = type[:-1]
			if indirections >= 2:
				break
		type = type.strip()
		if type[-3:] == "Ref":
			indirections += 1
		return indirections > 1
	
	def __str__(self):
		if self.name == None:
			return self.type
		return "%s: %s" % (self.name, self.type)
	
	def __repr__(self):
		return "<C Param: %r %r>" % (self.type, self.name)

class CPrototype(object):
	def __init__(self, returnType, name, parameters):
		self.returnType = returnType.strip()
		self.name = name.strip()
		self.params = CParameter.parse(parameters)
	
	def __str__(self):
		return "%s %s(%s)" % (self.returnType, self.name, ", ".join(str(p) for p in self.params))
	
	def __repr__(self):
		return "<C Prototype: %r %r %r>" % (self.returnType, self.name, self.params)

enumCaseRE = re.compile("\s*([^,]+)")

class CEnum(object):
	def __init__(self, name, body):
		self.name = name
		self.cases = {}
		nextValue = 0
		for case in enumCaseRE.findall(body):
			parts = [v.strip() for v in case.split('=')]
			if len(parts) == 2:
				nextValue = eval(parts[1])
			self.cases[parts[0]] = nextValue
			nextValue += 1
	
	def __repr__(self):
		return "<CEnum: %r %r>" % (self.name, self.cases)

prototypes = []
enums = {}
callbacks = {}
classes = {}

class PythonParameter(object):
	def __init__(self, type, generic = ""):
		self.type = type
		self.generic = generic
	
	def __str__(self):
		if self.generic == "":
			return self.type
		return "%s(%s)" % (self.type, self.generic)

class PythonMethod(object):
	def __init__(self, cFunction):
		if cFunction.name == "LLVMConstIntGetZExtValue":
			sys.stderr.write("got zextvalue\n")
		if cFunction.returnType in callbacks:
			raise ValueError("callback type %s" % cFunction.returnType)

		self.function = cFunction
		self.name = self.function.name[4:]
		self.selfType = None
		self.params = PythonMethod.convertParamList(cFunction.params)
		if cFunction.returnType == "void":
			self.returnType = PythonParameter("void")
		else:
			self.returnType = PythonMethod.convertParamList([CParameter(cFunction.returnType, "")])[0]
	
	@staticmethod
	def convertParamList(list):
		countConvention = ["count", "num", "length"]
		params = []
		prevPointerType = None
		for param in list:
			if param in callbacks:
				raise ValueError("of callback type %s" % cFunction.returnType)
			
			if prevPointerType != None:
				lowerName = param.name.lower()
				for conv in countConvention:
					if lowerName.find(conv) != -1:
						params.append(PythonParameter("list", prevPointerType))
						prevPointerType = None
						break
				else:
					raise ValueError("of uncertain bounds for double-pointer type '%s'" % prevPointerType)
			elif param.type == "const char *" or param.type == "const char*":
				params.append(PythonParameter("string"))
			else:
				refType = param.getRefType()
				if param.isDoublePointer():
					if refType == None:
						raise ValueError("of non-ref double-pointer type '%s'" % param)
					prevPointerType = refType
				elif refType != None:
					params.append(PythonParameter("object", refType))
				elif param.type in enums:
					params.append(PythonParameter("int", param.type))
				elif param.type == "unsigned":
					params.append(PythonParameter("int"))
				elif param.type == "unsigned long long":
					params.append(PythonParameter("int"))
				elif param.type == "long long":
					params.append(PythonParameter("int"))
				elif param.type == "LLVMBool":
					params.append(PythonParameter("bool"))
				else:
					raise ValueError("of unhandled type '%s'" % param)
		
		if prevPointerType != None:
			raise ValueError("of uncertain bounds for double-pointer type %s" % prevPointerType)
		
		return params
	
	def inferSelf(self):
		if self.selfType != None:
			return self.selfType
		
		if len(self.params) == 0:
			raise ValueError("cannot infer self type from empty parameter list")
		
		if self.params[0].type != "object":
			raise ValueError("cannot infer self type as non-reference type %s" % self.params[0])
		
		self.selfType = self.params[0].generic
		self.params = self.params[1:]
		return self.selfType

class PythonClass(object):
	def __init__(self, refType):
		self.refType = refType
		self.methods = []
	
	def name(self):
		return self.refType[4:-3]
	
	def addMethod(self, method):
		self.methods.append(method)

#
# Input parsing starts here
#

prototypeRE = re.compile("([a-zA-Z][a-zA-Z0-9\s*]+?)([a-zA-Z0-9]+)\(([^)]+)\);", re.M | re.S)
enumRE = re.compile("typedef\s+enum\s+{\s+([^}]+)}\s+([^;]+);", re.S)
callbackRE = re.compile(r"typedef ([^(]+)\(\*([^)]+)\)\s*\(([^)]+)\);")

contents = ""
includeLine = False
includeLineRe = re.compile(r'^# [0-9]+ "(.+)"')
for line in sys.stdin:
	match = includeLineRe.match(line)
	if match != None:
		# heuristic to determine whether we're in a llvm-c header or not
		includeLine = match.group(1).find("llvm-c/") != -1
	elif includeLine:
		contents += line

for returnType, name, parameters in callbackRE.findall(contents):
	proto = CPrototype(returnType, name, parameters)
	callbacks[proto.name] = proto

for body, name in enumRE.findall(contents):
	# HACKHACK LLVM 3.9: deprecated enum causes name conflict
	if name != "LLVMAttribute":
		e = CEnum(name, body)
		enums[e.name] = e

for returnType, name, parameters in prototypeRE.findall(contents):
	p = CPrototype(returnType, name, parameters)
	try:
		method = PythonMethod(p)
		classType = method.inferSelf()
		if classType not in classes:
			classes[classType] = PythonClass(classType)
		classes[classType].addMethod(method)
	except ValueError as message:
		sys.stderr.write("cannot use %s because %s\n" % (p, message))

#
# do post-processing here
#
del classes["MemoryBuffer"]

for method in classes["Context"].methods:
	inctx = "InContext"
	if method.name[-len(inctx):] == inctx:
		method.name = method.name[:-len(inctx)]

valueMethods = []
for method in classes["Value"].methods:
	if method.name.startswith("Const") and method.returnType.generic == "Value":
		# we should probably put them somewhere else instead of outright removing them
		sys.stderr.write("Removing %s because it's probably not a Value method\n" % method.name)
		continue
	valueMethods.append(method)
classes["Value"].methods = valueMethods

e = enums["LLVMRealPredicate"]
enums["LLVMPredicate"] = e
newDict = {}
for key in e.cases:
	newDict[key[4:]] = e.cases[key]
e.cases = newDict
del enums["LLVMRealPredicate"]

for key in classes:
	classes[key].methods.sort(key = lambda m: m.name)

#
# code generation starts here
#

print("#pragma clang diagnostic push")
print("#pragma clang diagnostic ignored \"-Wshorten-64-to-32\"")
print()
print("#include \"bindings.h\"")
print("#include <llvm-c/Core.h>")
print("#include <memory>")
print()

methodNoArgsPrototypeTemplate = """static PyObject* %s(Py_LLVM_Wrapped<%s>* self)"""
methodArgsPrototypeTemplate = """static PyObject* %s(Py_LLVM_Wrapped<%s>* self, PyObject* args)"""

methodTableEntryTemplate = """\t{"%s", (PyCFunction)&%s, METH_%s, "Wrapper for %s"},\n"""
methodTableTemplate = """static PyMethodDef %s_methods[] = {
%s\t{nullptr}\n};
"""

typeObjectTemplate = """PyTypeObject %s_Type = {
	PyObject_HEAD_INIT(nullptr)
	.tp_name = "llvm.%s",
	.tp_basicsize = %s,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "Wrapper type for %s",
	.tp_methods = %s_methods,
};
"""

methodImplementations = ""
prefix = "Py_"

for classKey in classes:
	klass = classes[classKey]
	llvmName = "LLVM%sRef" % classKey
	typeName = "%s%s" % (prefix, llvmName[:-3])
	
	sys.stderr.write("class %s:\n" % classKey)
	
	tableEntries = ""
	# prototypes
	for method in klass.methods:
		sys.stderr.write("\tdef %s(%s) -> %s\n" % (method.name, ", ".join(str(x) for x in method.params), method.returnType))
		methodCName = "%s_%s" % (typeName, method.name)
		if len(method.params) == 0:
			args = "NOARGS"
			prototype = methodNoArgsPrototypeTemplate % (methodCName, llvmName)
			print(prototype + ";")
		else:
			args = "VARARGS"
			prototype = methodArgsPrototypeTemplate % (methodCName, llvmName)
			print(prototype + ";")
		
		tableEntries += methodTableEntryTemplate % (method.name, methodCName, args, method.function.name)
		
		i = 0
		methodImplementations += prototype + "\n{\n"
		paramString = ""
		addresses = []
		for param in method.params:
			if param.type == "string":
				methodImplementations += "\tconst char* arg%i;\n" % i
				paramString += "s"
				addresses.append("&arg%i" % i)
			elif param.type == "int":
				methodImplementations += "\tlong long arg%i;\n" % i
				paramString += "L"
				addresses.append("&arg%i" % i)
			else:
				paramString += "O"
				if param.type == "object":
					methodImplementations += "\tPy_LLVM_Wrapped<LLVM%sRef>* arg%i;\n" % (param.generic, i)
					paramString += "!"
					addresses.append("&%sLLVM%s_Type" % (prefix, param.generic))
				else:
					methodImplementations += "\tPyObject* arg%i;\n" % i
					if param.type == "bool":
						paramString += "!"
						addresses.append("&PyBool_Type")
				addresses.append("&arg%i" % i)
			i += 1
		
		if args == "NOARGS": # NOARGS
			# easy case.
			returnedExpression = "%s(self->obj)" % method.function.name
		else:
			# hard case.
			methodImplementations += "\tif (!PyArg_ParseTuple(args, \"%s\", %s))\n" % (paramString, ", ".join(addresses))
			methodImplementations += "\t{\n\t\treturn nullptr;\n\t}\n\n"
			
			cParams = ["self->obj"]
			i = 0
			for param in method.params:
				if param.type == "string":
					cParams.append("arg%i" % i)
				elif param.type == "int":
					if param.generic == "":
						cParams.append("arg%i" % i)
					else:
						cParams.append("(%s)arg%i" % (param.generic, i))
				elif param.type == "bool":
					methodImplementations += "\tLLVMBool carg%i = PyObject_IsTrue(arg%i);\n" % (i, i)
					cParams.append("carg%i" % i)
				elif param.type == "object":
					cParams.append("arg%i->obj" % i)
				elif param.type == "list":
					# hardest case.
					llvmType = "LLVM%sRef" % param.generic
					methodImplementations += "\tauto seq%i = TAKEREF PySequence_Fast(arg%i, \"argument %i expected to be a sequence\");\n" % (i, i, i + 1)
					methodImplementations += "\tif (!seq%i)\n" % i
					methodImplementations += "\t{\n\t\treturn nullptr;\n\t}\n"
					methodImplementations += "\tPy_ssize_t len%i = PySequence_Size(seq%i.get());\n" % (i, i)
					methodImplementations += "\tstd::unique_ptr<%s[]> array%i(new %s[static_cast<size_t>(len%i)]);\n" % (llvmType, i, llvmType, i)
					methodImplementations += "\tfor (Py_ssize_t i = 0; i < len%i; ++i)\n" % i
					methodImplementations += "\t{\n"
					methodImplementations += "\t\tauto wrapped = (Py_LLVM_Wrapped<%s>*)PySequence_Fast_GET_ITEM(seq%i.get(), i);\n" % (llvmType, i)
					methodImplementations += "\t\tarray%i[static_cast<size_t>(i)] = wrapped->obj;\n" % i
					methodImplementations += "\t}\n"
					cParams.append("array%i.get()" % i)
					cParams.append("len%i" % i)
				i += 1
			returnedExpression = "%s(%s)" % (method.function.name, ", ".join(cParams))
		
		if method.returnType.type == "object":
			returnTypeString = "Py_LLVM_Wrapped<LLVM%sRef>" % method.returnType.generic
			objectType = "%sLLVM%s_Type" % (prefix, method.returnType.generic)
			methodImplementations += "\tauto callReturn = %s;\n" % returnedExpression
			methodImplementations += "\tif (callReturn == nullptr)\n"
			methodImplementations += "\t{\n"
			methodImplementations += "\t\tPy_RETURN_NONE;\n"
			methodImplementations += "\t}\n"
			methodImplementations += "\t%s* result = PyObject_New(%s, &%s);\n" % (returnTypeString, returnTypeString, objectType)
			methodImplementations += "\tresult->obj = callReturn;\n"
			methodImplementations += "\treturn (PyObject*)result;\n"
		elif method.returnType.type == "string":
			methodImplementations += "\treturn PyString_FromString(%s);\n" % returnedExpression
		elif method.returnType.type == "int":
			methodImplementations += "\treturn PyInt_FromLong(static_cast<long>(%s));\n" % returnedExpression
		elif method.returnType.type == "bool":
			methodImplementations += "\treturn PyBool_FromLong(%s);\n" % returnedExpression
		elif method.returnType.type == "void":
			methodImplementations += "\t%s;\n" % returnedExpression
			methodImplementations += "\tPy_RETURN_NONE;\n"
		else:
			methodImplementations += "#error Implement return type %s" % method.returnType.type
		methodImplementations += "}\n\n"
	print()
	
	sys.stderr.write("\n")
	
	# method table
	print(methodTableTemplate % (typeName, tableEntries))
	print(typeObjectTemplate % (typeName, classKey, "sizeof(Py_LLVM_Wrapped<%s>)" % llvmName, llvmName, typeName))

# enum types here
print(methodTableTemplate % ("no", ""))
for enumKey in enums:
	typeName = "%s%s" % (prefix, enumKey)
	print(typeObjectTemplate % (typeName, enumKey[4:], "sizeof(PyObject)", "enum " + enumKey, "no"))

print(methodImplementations)

print("PyMODINIT_FUNC initLlvmModule(PyObject** module)")
print("{")
for classKey in classes:
	typeObjName = "%sLLVM%s_Type" % (prefix, classKey)
	print("\tif (PyType_Ready(&%s) < 0) return;" % typeObjName)

for enumKey in enums:
	typeObjName = "%s%s_Type" % (prefix, enumKey)
	print("\tif (PyType_Ready(&%s) < 0) return;" % typeObjName)

print()
for enumKey in enums:
	typeObjName = "%s%s_Type" % (prefix, enumKey)
	enum = enums[enumKey]
	for key in enum.cases:
		print("\tPyDict_SetItemString(%s.tp_dict, \"%s\", (TAKEREF PyInt_FromLong(%i)).get());" % (typeObjName, key[4:], enum.cases[key]))
	print()

print()
print("\t*module = Py_InitModule(\"llvm\", nullptr);")
for classKey in classes:
	typeObjName = "%sLLVM%s_Type" % (prefix, classKey)
	print("\tPy_INCREF(&%s);" % typeObjName)
for enumKey in enums:
	typeObjName = "%s%s_Type" % (prefix, enumKey)
	print("\tPy_INCREF(&%s);" % typeObjName)

for classKey in classes:
	typeObjName = "%sLLVM%s_Type" % (prefix, classKey)
	print("\tPyModule_AddObject(*module, \"%s\", (PyObject*)&%s);" % (classKey, typeObjName))
for enumKey in enums:
	typeObjName = "%s%s_Type" % (prefix, enumKey)
	print("\tPyModule_AddObject(*module, \"%s\", (PyObject*)&%s);" % (enumKey[4:], typeObjName))

print("}")
print()
print("#pragma clang diagnostic pop")
