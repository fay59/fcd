# -*- coding: UTF-8 -*-

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

# post-processing
for method in classes["Context"].methods:
	inctx = "InContext"
	if method.name[-len(inctx):] == inctx:
		method.name = method.name[:-len(inctx)]

valueMethods = []
for method in classes["Value"].methods:
	if not method.name.startswith("Const"):
		valueMethods.append(method)
classes["Value"].methods = valueMethods

for className in classes:
	print "class %s:" % className
	for method in classes[className].methods:
		print "\tdef %s(%s) -> %s" % (method.name, ", ".join(str(x) for x in method.params), method.returnType)
	print