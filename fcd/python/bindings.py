# -*- coding: UTF-8 -*-

import fnmatch
import re
import os
import sys

if len(sys.argv) != 2:
	sys.stderr.write("usage: %s llvm-c-header-dir" % sys.argv[0])
	sys.exit(1)

def pathComponents(path):
	folders = []
	while path != "" and path != "/":
		path, last = os.path.split(path)
		folders.append(last)
	return folders[::-1]

parametersRE = re.compile("([^,]+\W)(\w+)", re.MULTILINE | re.S)

def isDoublePointer(type):
	indirections = 0
	while type[-1] == '*':
		indirections += 1
		type = type[:-1]
		if indirections >= 2:
			break
	type = type.strip()
	if type[-3:] == "Ref":
		indirections++
	return indirections > 1

class Parameter(object):
	def __init__(self, type, name):
		self.type = type
		self.name = name
		self.countParam = 0

class Prototype(object):
	def __init__(self, returnType, name, parameters):
		self.returnType = returnType.strip()
		self.name = name.strip()
		for type, param in parametersRE.findall(parameters):
			type = type.strip()
			param = param.strip()
			if isDoublePointer(type):
				

commentRE = re.compile("/\\*(.+?)\\*/", re.S)
prototypeRE = re.compile("^([a-zA-Z][a-zA-Z0-9\s*]+?)([a-zA-Z0-9]+)\(([^)]+)\);", re.M | re.S)

includes = []
prototypes = []

for root, dirnames, filenames in os.walk(sys.argv[1]):
	for filename in fnmatch.filter(filenames, "*.h"):
		joined = os.path.join(root, filename)
		components = pathComponents(os.path.splitext(joined)[0])
		moduleName = ".".join(components[components.index("llvm-c")+1:])
		print "%s:" % moduleName
		
		with open(joined) as fd:
			contents = commentRE.sub("", fd.read())
		
		includes.append(os.path.join("llvm-c", filename))
		for returnType, name, parameters in prototypeRE.findall(contents):
			print "%s %s:" % (returnType.strip(), name),
			for type, param in parametersRE.findall(parameters):
				type = type.strip()
				print "(%s) %s," % (type, param),
			print
		print
