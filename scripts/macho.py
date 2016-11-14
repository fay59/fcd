import bisect
import struct
import sys

FAT_MAGIC = "\xca\xfe\xba\xbe"
MACH_MAGIC32 = "\xfe\xed\xfa\xce"
MACH_MAGIC64 = "\xfe\xed\xfa\xcf"

LC_SEGMENT = 1
LC_SYMTAB = 2
LC_DYSYMTAB = 0xb
LC_LOAD_DYLIB = 0xc
LC_SEGMENT_64 = 0x19
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_FUNCTION_STARTS = 0x26
LC_MAIN = 0x80000028

BIND_OPCODE_DONE = 0
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 1
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 2
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 3
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 4
BIND_OPCODE_SET_TYPE_IMM = 5
BIND_OPCODE_SET_ADDEND_SLEB = 6
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 7
BIND_OPCODE_ADD_ADDR_ULEB = 8
BIND_OPCODE_DO_BIND = 9
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 10
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 11
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 12

vm_prot_read = 1
vm_prot_write = 2
vm_prot_execute = 4

class FatMachO(object):
	def __init_fat(self, endianness, data):
		fat_header = endianness + "II"
		fat_arch = endianness + "4sIIII"
		fat_arch_size = struct.calcsize(fat_arch)
		
		magic, count = struct.unpack(fat_header, data)
		offset = struct.calcsize(fat_header)
		for i in range(count):
			cpu, cpuSubtype, offset, size, align = struct.unpack(fat_arch, data[offset:])
			offset += fat_arch_size
			self.executables.append(MachO(data[offset:offset+size]))
	
	def __init__(self, data):
		self.executables = []
		magic = data[:4]
		if magic == FAT_MAGIC:
			self.__init_fat(">", data)
		elif magic == FAT_MAGIC[::-1]:
			self.__init_fat("<", data)
		elif magic == MACH_MAGIC32 or magic == MACH_MAGIC64 or magic == MACH_MAGIC32[::-1] or magic == MACH_MAGIC64[::-1]:
			self.executables.append(MachO(data))
		else:
			raise ValueError, "%r is not a valid magic value for a Mach-O file!" % magic

class MachOSegment(object):
	def __init__(self, name, vmAddress, vmSize, fileOffset, fileSize, protection):
		self.name = name
		self.virtualAddress = vmAddress
		self.virtualSize = vmSize
		self.fileOffset = fileOffset
		self.fileSize = fileSize
		self.protection = protection
	
	def allows(self, mask):
		return self.protection & mask == mask
	
	def __repr__(self):
		permissions = ""
		modes = [(vm_prot_read, "R"), (vm_prot_write, "W"), (vm_prot_execute, "X")]
		for bitmask, char in modes:
			permissions += char if self.allows(bitmask) else "."
				
		return "<MachOSegment(%r, VM 0x%x-0x%x, file %u-%u, %s)>" % (self.name, self.virtualAddress, self.virtualAddress + self.virtualSize, self.fileOffset, self.fileOffset + self.fileSize, permissions)

class MachO(object):
	def __init__(self, data, parseFunctionStarts = True):
		magic = data[:4]
		if magic == MACH_MAGIC32:
			self.endianness = ">"
			self.bitness = 32
		elif magic == MACH_MAGIC32[::-1]:
			self.endianness = "<"
			self.bitness = 32
		elif magic == MACH_MAGIC64:
			self.endianness = ">"
			self.bitness = 64
		elif magic == MACH_MAGIC64[::-1]:
			self.endianness = "<"
			self.bitness = 64
		else:
			raise ValueError, "%r is not a valid magic value for a Mach-O executable!" % magic
		
		self.segmentBases = []
		self.segments = {}
		self.entryPoints = []
		self.__entryPointSet = set()
		self.loadedDylibs = []
		self.__stubs = []
		self.__data = data
		if self.bitness == 32:
			format = self.endianness + "4sIIIIII"
			loaderCommandOffset = struct.calcsize(format)
			magic, self.cpu, self.cpuSubtype, fileType, nCmds, sizeOfCmd, self.flags = struct.unpack(format, data)
		else:
			format = self.endianness + "4sIIIIIII"
			loaderCommandOffset = struct.calcsize(format)
			magic, self.cpu, self.cpuSubtype, fileType, nCmds, sizeOfCmd, self.flags, reserved = struct.unpack(format, data[:loaderCommandOffset])
		
		commands = data[loaderCommandOffset:loaderCommandOffset+sizeOfCmd]
		commandOffset = 0
		commandFormat = self.endianness + "II"
		commandHeaderSize = struct.calcsize(commandFormat)
		for i in range(nCmds):
			command, commandSize = struct.unpack(commandFormat, commands[commandOffset:commandOffset+commandHeaderSize])
			commandBytes = commands[commandOffset+commandHeaderSize:commandOffset+commandSize]
			commandOffset += commandSize
			if command == LC_SEGMENT:
				if self.bitness == 32:
					self.__doSegment(commandBytes)
				else:
					raise ValueError, "LC_SEGMENT command in 64-bit executable!"
			elif command == LC_SEGMENT_64:
				if self.bitness == 64:
					self.__doSegment(commandBytes)
				else:
					raise ValueError, "LC_SEGMENT_64 in 32-bit executable!"
			elif command == LC_SYMTAB:
				self.__doSymtab(commandBytes)
			elif command == LC_DYLD_INFO or command == LC_DYLD_INFO_ONLY:
				self.__doDyldInfo(commandBytes)
			elif command == LC_MAIN:
				self.__doMain(commandBytes)
			elif command == LC_FUNCTION_STARTS and parseFunctionStarts:
				# Gate behind an opt-out setting because LC_FUNCTION_STARTS is
				# particularly easy to mess with.
				self.__doFunctionStarts(commandBytes)
			elif command == LC_LOAD_DYLIB:
				self.__doLoadDylib(commandBytes)

		# process stubs
		self.stubs = {}
		for segmentIndex, segmentOffset, libOrdinal, name in self.__stubs:
			try:
				segment = self.segments[self.segmentBases[segmentIndex]]
				if segmentOffset + self.bitness / 8 > segment.virtualSize:
					continue
				if libOrdinal == -2:
					libName = None
				elif libOrdinal == -1:
					libName = "<main executable>"
				elif libOrdinal == 0:
					libName = "<self>"
				elif libOrdinal > 0:
					libName = self.loadedDylibs[libOrdinal-1]
				else:
					continue
				address = segment.virtualAddress + segmentOffset
				self.stubs[address] = (libName, name)
			except:
				stub = (segmentIndex, segmentOffset, libOrdinal, name)
				sys.stderr.write("failed to bind stub %r!\n" % (stub,))
		
		try:
			dataOffset, dataSize = self.__functionStarts
			data = self.__data[dataOffset:dataOffset + dataSize]
			offset, index = self.__readUleb(data, 0)
			address = self.__text.virtualAddress + offset
			if address not in self.__entryPointSet:
				self.entryPoints.append((address, "func_%0*x" % (self.bitness / 4, address)))
			while index != dataSize:
				offset, index = self.__readUleb(data, index)
				address += offset
				if address not in self.__entryPointSet:
					self.entryPoints.append((value, "func_%x" % address))
					self.__entryPointSet.add(value)
		except: pass
		
		try:
			if self.__entryPointOffset < self.__text.fileSize:
				address = self.__text.virtualAddress + self.__entryPointOffset
				if self.__entryPointOffset not in self.__entryPointSet:
					self.entryPoints.add((address, "entry_%x" % self.__entryPointOffset))
					self.__entryPointSet.add(self.__entryPointOffset)
			del self.__entryPointOffset
		except: pass
		
		del self.__stubs
		del self.__data
		del self.__functionStarts
		del self.__entryPointSet
	
	def segmentAt(self, virtualAddress):
		segmentIndex = bisect.bisect_right(self.segmentBases, virtualAddress)
		if segmentIndex:
			segmentMaybeStart = self.segmentBases[segmentIndex-1]
			thisSegmentInfo = self.segments[segmentMaybeStart]
			pointerOffset = virtualAddress - segmentMaybeStart
			if pointerOffset <= thisSegmentInfo.fileSize:
				return thisSegmentInfo
		return None
	
	def __doSegment(self, commandBytes):
		if self.bitness == 32:
			format = self.endianness + "16sIIIIIIII"
		else:
			format = self.endianness + "16sQQQQIIII"
		
		size = struct.calcsize(format)
		segmentName, vmAddress, vmSize, fileOffset, fileSize, maxProt, initProt, nSections, flags = struct.unpack(format, commandBytes[:size])
		zeroTerminator = segmentName.find("\0")
		if zeroTerminator != -1:
			segmentName = segmentName[:zeroTerminator]
		
		segment = MachOSegment(segmentName, vmAddress, vmSize, fileOffset, fileSize, initProt)
		bisect.insort(self.segmentBases, vmAddress)
		self.segments[vmAddress] = segment
		if segmentName == "__TEXT":
			self.__text = segment
	
	def __doSymtab(self, commandBytes):
		format = self.endianness + "IIII"
		symtabOffset, nSyms, strtabOffset, strtabSize = struct.unpack(format, commandBytes)
		
		if self.bitness == 32:
			nlist = self.endianness + "IBBHI"
		else:
			nlist = self.endianness + "IBBHQ"
		nlistSize = struct.calcsize(nlist)
		symtab = self.__data[symtabOffset:symtabOffset + nSyms * nlistSize]
		for i in range(nSyms):
			strtabIndex, type, sect, desc, value = struct.unpack(nlist, symtab[i*nlistSize : (i+1)*nlistSize])
			if type & 0xe == 0:
				# skip undefined symbols
				continue
			
			segment = self.segmentAt(value)
			if segment == None:
				continue
			
			if segment.fileOffset == 0 and segment.virtualAddress == value:
				# exclude Mach header symbol, which is at the start of the executable file
				continue
			if not segment or not segment.allows(vm_prot_execute):
				# skip non-executable symbols
				continue
			
			name = ""
			nameStart = strtabOffset + strtabIndex
			if nameStart < len(self.__data):
				nameEnd = self.__data.find("\0", nameStart)
				if nameEnd != -1:
					name = self.__data[nameStart:nameEnd]
			if value not in self.__entryPointSet:
				self.entryPoints.append((value, name))
				self.__entryPointSet.add(value)
	
	def __doDyldInfo(self, commandBytes):
		format = self.endianness + "IIIIIIIIII"
		rebaseOffset, rebaseSize, bindOffset, bindSize, weakBindOffset, weakBindSize, lazyBindOffset, lazyBindSize, exportOffset, exportSize = struct.unpack(format, commandBytes)
		self.__parseImports(bindOffset, bindSize)
		self.__parseImports(weakBindOffset, weakBindSize)
		self.__parseImports(lazyBindOffset, lazyBindSize)
	
	def __doMain(self, commandBytes):
		format = self.endianness + "QQ"
		self.__entryPointOffset, stackSize = struct.unpack(format, commandBytes)
	
	def __doLoadDylib(self, commandBytes):
		format = self.endianness + "IIII"
		structSize = struct.calcsize(format)
		nameStart, timestamp, currentVersion, compatVersion = struct.unpack(format, commandBytes[:structSize])
		nameEnd = commandBytes.find("\0", nameStart)
		name = commandBytes[nameStart:nameEnd]
		self.loadedDylibs.append(name)
	
	def __doFunctionStarts(self, commandBytes):
		format = self.endianness + "II"
		self.__functionStarts = struct.unpack(format, commandBytes)
	
	def __parseImports(self, offset, size):
		pointerWidth = self.bitness / 8
		slice = self.__data[offset:offset+size]
		index = 0
		
		name = ""
		segment = 0
		segmentOffset = 0
		libOrdinal = 0
		
		def addStub():
			self.__stubs.append((segment, segmentOffset, libOrdinal, name))
		
		while index != len(slice):
			byte = ord(slice[index])
			opcode = byte >> 4
			immediate = byte & 0xf
			index += 1
			
			if opcode == BIND_OPCODE_DONE:
				pass
			elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
				libOrdinal = immediate
			elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
				libOrdinal, index = self.__readUleb(slice, index)
			elif opcode == BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
				libOrdinal = -immediate
			elif opcode == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
				nameEnd = slice.find("\0", index)
				name = slice[index:nameEnd]
				index = nameEnd
			elif opcode == BIND_OPCODE_SET_TYPE_IMM:
				pass
			elif opcode == BIND_OPCODE_SET_ADDEND_SLEB:
				_, index = self.__readUleb(slice, index)
			elif opcode == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
				segment = immediate
				segmentOffset, index = self.__readUleb(slice, index)
			elif opcode == BIND_OPCODE_ADD_ADDR_ULEB:
				addend, index = self.__readUleb(slice, index)
				segmentOffset += addend
			elif opcode == BIND_OPCODE_DO_BIND:
				addStub()
			elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
				addStub()
				addend, index = self.__readUleb(slice, index)
				segmentOffset += addend
			elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
				addStub()
				segmentOffset += immediate * pointerWidth
			elif opcode == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
				times, index = self.__readUleb(slice, index)
				skip, index = self.__readUleb(slice, index)
				for i in range(times):
					addStub()
					segmentOffset += pointerWidth * skip
			else:
				sys.stderr.write("warning: unknown bind opcode %u, immediate %u\n" % (opcode, immediate))
	
	def __readUleb(self, data, offset):
		byte = ord(data[offset])
		offset += 1
		
		result = byte & 0x7f
		shift = 7
		while byte & 0x80:
			byte = ord(data[offset])
			result |= (byte & 0x7f) << shift
			shift += 7
			offset += 1
		return (result, offset)

executable = None

################################################################################
# fcd interface below
################################################################################

executableType = "Mach-O Executable"
entryPoints = []

def init(data):
	global entryPoints
	global executable
	
	fat = FatMachO(data)
	if len(fat.executables) != 1:
		raise ValueError, "File contains %i executables! Specialize script to select one." % len(fat.executables)
	
	executable = fat.executables[0]
	entryPoints = executable.entryPoints

def getStubTarget(target):
	if target in executable.stubs:
		return executable.stubs[target]
	return None

def mapAddress(address):
	segmentIndex = bisect.bisect_right(executable.segmentBases, address)
	if segmentIndex:
		segmentMaybeStart = executable.segmentBases[segmentIndex-1]
		thisSegmentInfo = executable.segments[segmentMaybeStart]
		pointerOffset = address - segmentMaybeStart
		if pointerOffset <= thisSegmentInfo.virtualSize:
			return thisSegmentInfo.fileOffset + pointerOffset
	return None
