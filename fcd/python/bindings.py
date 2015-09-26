# -*- coding: UTF-8 -*-

#
# bindings.py
# Copyright (C) 2015 Félix Cloutier.
# All Rights Reserved.
#
# This file is part of fcd.
# 
# fcd is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# fcd is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with fcd.  If not, see <http://www.gnu.org/licenses/>.
#
# As a special exception to the GPL license, the output of this script
# may be reused for any purpose, under the licensing scheme that you
# prefer.
#
# (run me on a preprocessed llvm-c/Core.h without its includes)
#

import re
import os
import string
import sys

if len(sys.argv) != 2:
	sys.stderr.write("usage: %s preprocessed-header-file" % sys.argv[0])
	sys.exit(1)

def pathComponents(path):
	folders = []
	while path != "" and path != "/":
		path, last = os.path.split(path)
		folders.append(last)
	return folders[::-1]

llvmTypeRE = re.compile("LLVM(.+)Ref")

class CParameter(object):
	@staticmethod
	def parse(paramString):
		wordCharset = string.letters + string.digits
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
		if cFunction.returnType in callbacks:
			raise ValueError, "callback type %s" % cFunction.returnType

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
				raise ValueError, "of callback type %s" % cFunction.returnType
			
			if prevPointerType != None:
				lowerName = param.name.lower()
				for conv in countConvention:
					if lowerName.find(conv) != -1:
						params.append(PythonParameter("list", prevPointerType))
						prevPointerType = None
						break
				else:
					raise ValueError, "of uncertain bounds for double-pointer type '%s'" % prevPointerType
			elif param.type == "const char *" or param.type == "const char*":
				params.append(PythonParameter("string"))
			else:
				refType = param.getRefType()
				if param.isDoublePointer():
					if refType == None:
						raise ValueError, "of non-ref double-pointer type '%s'" % param
					prevPointerType = refType
				elif refType != None:
					params.append(PythonParameter("object", refType))
				elif param.type in enums:
					params.append(PythonParameter("int", param.type))
				elif param.type == "unsigned":
					params.append(PythonParameter("int"))
				elif param.type == "LLVMBool":
					params.append(PythonParameter("bool"))
				else:
					raise ValueError, "of unhandled type '%s'" % param
		
		if prevPointerType != None:
			raise ValueError, "of uncertain bounds for double-pointer type %s" % prevPointerType
		
		return params
	
	def inferSelf(self):
		if self.selfType != None:
			return self.selfType
		
		if len(self.params) == 0:
			raise ValueError, "cannot infer self type from empty parameter list"
		
		if self.params[0].type != "object":
			raise ValueError, "cannot infer self type as non-reference type %s" % self.params[0]
		
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

prototypeRE = re.compile("^([a-zA-Z][a-zA-Z0-9\s*]+?)([a-zA-Z0-9]+)\(([^)]+)\);", re.M | re.S)
enumRE = re.compile("typedef\s+enum\s+{\s+([^}]+)}\s+([^;]+);", re.S)
callbackRE = re.compile(r"typedef ([^(]+)\(\*([^)]+)\)\s*\(([^)]+)\);")

with open(sys.argv[1]) as fd:
	contents = fd.read()

moduleName = os.path.splitext(os.path.basename(sys.argv[1]))[0]

for returnType, name, parameters in callbackRE.findall(contents):
	proto = CPrototype(returnType, name, parameters)
	callbacks[proto.name] = proto

for body, name in enumRE.findall(contents):
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
	except ValueError, message:
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
	if not method.name.startswith("Const"):
		valueMethods.append(method)
classes["Value"].methods = valueMethods

#
# code generation starts here
#

print "#pragma clang diagnostic push"
print "#pragma clang diagnostic ignored \"-Wshorten-64-to-32\""
print
print "#include \"bindings.h\""
print "#include <llvm-c/Core.h>"
print "#include <memory>"
print
print """template<typename WrappedType>
struct Py_LLVM_Wrapped
{
	PyObject_HEAD
	WrappedType obj;
};
"""

methodNoArgsPrototypeTemplate = """static PyObject* %s(Py_LLVM_Wrapped<%s>* self)"""
methodArgsPrototypeTemplate = """static PyObject* %s(Py_LLVM_Wrapped<%s>* self, PyObject* args)"""

methodTableEntryTemplate = """\t{"%s", (PyCFunction)&%s, METH_%s, "Wrapper for %s"},\n"""
methodTableTemplate = """static PyMethodDef %s_methods[] = {
%s\t{nullptr}\n};
"""

typeObjectTemplate = """PyTypeObject %s_Type = {
	PyObject_HEAD_INIT(nullptr)
	.tp_name = "llvm.%s",
	.tp_basicsize = sizeof(Py_LLVM_Wrapped<%s>),
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
	
	tableEntries = ""
	# prototypes
	for method in klass.methods:
		methodCName = "%s_%s" % (typeName, method.name)
		if len(method.params) == 0:
			args = "NOARGS"
			prototype = methodNoArgsPrototypeTemplate % (methodCName, llvmName)
			print prototype + ";"
		else:
			args = "VARARGS"
			prototype = methodArgsPrototypeTemplate % (methodCName, llvmName)
			print prototype + ";"
		
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
					methodImplementations += "\tPyObject* seq%i = PySequence_Fast(arg%i, \"argument %i expected to be a sequence\");\n" % (i, i, i + 1)
					methodImplementations += "\tif (seq%i == nullptr)\n" % i
					methodImplementations += "\t{\n\t\treturn nullptr;\n\t}\n"
					methodImplementations += "\tPy_ssize_t len%i = PySequence_Size(seq%i);\n" % (i, i)
					methodImplementations += "\tstd::unique_ptr<%s[]> array%i(new %s[len%i]);\n" % (llvmType, i, llvmType, i)
					methodImplementations += "\tfor (Py_ssize_t i = 0; i < len%i; ++i)\n" % i
					methodImplementations += "\t{\n"
					methodImplementations += "\t\tauto wrapped = (Py_LLVM_Wrapped<%s>*)PySequence_Fast_GET_ITEM(seq%i, i);\n" % (llvmType, i)
					methodImplementations += "\t\tarray%i[i] = wrapped->obj;\n" % i
					methodImplementations += "\t}\n"
					cParams.append("array%i.get()" % i)
					cParams.append("len%i" % i)
				i += 1
			returnedExpression = "%s(%s)" % (method.function.name, ", ".join(cParams))
		
		if method.returnType.type == "object":
			returnTypeString = "Py_LLVM_Wrapped<LLVM%sRef>" % method.returnType.generic
			objectType = "%sLLVM%s_Type" % (prefix, method.returnType.generic)
			methodImplementations += "\t%s* result = (%s*)PyType_GenericNew(&%s, nullptr, nullptr);\n" % (returnTypeString, returnTypeString, objectType)
			methodImplementations += "\tresult->obj = %s;\n" % returnedExpression
			methodImplementations += "\treturn (PyObject*)result;\n"
		elif method.returnType.type == "string":
			methodImplementations += "\treturn PyString_FromString(%s);\n" % returnedExpression
		elif method.returnType.type == "int":
			methodImplementations += "\treturn PyInt_FromLong(%s);\n" % returnedExpression
		elif method.returnType.type == "bool":
			methodImplementations += "\treturn PyBool_FromLong(%s);\n" % returnedExpression
		elif method.returnType.type == "void":
			methodImplementations += "\t%s;\n" % returnedExpression
			methodImplementations += "\tPy_RETURN_NONE;\n"
		else:
			methodImplementations += "#error Implement return type %s" % method.returnType.type
		methodImplementations += "}\n\n"
	print
	
	# method table
	print methodTableTemplate % (typeName, tableEntries)
	print typeObjectTemplate % (typeName, classKey, llvmName, llvmName, typeName)

print methodImplementations

print "PyMODINIT_FUNC initLlvmModule(PyObject** module)"
print "{"
for classKey in classes:
	typeObjName = "%sLLVM%s_Type" % (prefix, classKey)
	print "\tif (PyType_Ready(&%s) < 0) return;" % typeObjName
print
print "\t*module = Py_InitModule(\"llvm\", nullptr);"
for classKey in classes:
	typeObjName = "%sLLVM%s_Type" % (prefix, classKey)
	print "\tPy_INCREF(&%s);" % typeObjName
for classKey in classes:
	typeObjName = "%sLLVM%s_Type" % (prefix, classKey)
	print "\tPyModule_AddObject(*module, \"%s\", (PyObject*)&%s);" % (classKey, typeObjName)
print "}"
print
print "#pragma clang diagnostic pop"