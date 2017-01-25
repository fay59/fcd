//
// elf_executable.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#include "elf_executable.h"
#include "executable_errors.h"

#include <llvm/Support/raw_ostream.h>

#include <array>
#include <cstdint>
#include <deque>
#include <unordered_map>

using namespace llvm;
using namespace std;

namespace
{
	template<typename T>
	struct ptr_range
	{
		const T* a;
		const T* z;
		
		inline ptr_range() : a(nullptr), z(nullptr)
		{
		}
		
		inline ptr_range(const T* a, const T* z)
		: a(a), z(z)
		{
		}
		
		const T* begin() const { return a; }
		const T* end() const { return z; }
	};

	template<typename T>
	const T* bounded_cast(const uint8_t* begin, const uint8_t* end, size_t offset)
	{
		unsigned long long max;
		if (__builtin_uaddll_overflow(offset, sizeof(T), &max) || end < begin || static_cast<size_t>(end - begin) < max)
		{
			return nullptr;
		}
		
		return reinterpret_cast<const T*>(&begin[offset]);
	}

	template<typename T>
	ptr_range<T> bounded_cast(const uint8_t* begin, const uint8_t* end, size_t offset, size_t count)
	{
		unsigned long long max;
		if (__builtin_umulll_overflow(count, sizeof(T), &max) || __builtin_uaddll_overflow(offset, max, &max) || end < begin || static_cast<uint64_t>(end - begin) < max)
		{
			return ptr_range<T>();
		}
		
		return ptr_range<T>(reinterpret_cast<const T*>(&begin[offset]), reinterpret_cast<const T*>(&begin[max]));
	}

	struct Elf32Types
	{
		static constexpr size_t bits = 32;
		typedef uint16_t Half;
		typedef uint32_t Word;
		typedef int32_t Sword;
		typedef uint64_t Xword;
		typedef int64_t Sxword;
		typedef uint32_t Addr;
		typedef uint32_t Off;
		typedef uint16_t SectionIndex;
		typedef uint32_t SymbolIndex;
	};

	struct Elf64Types
	{
		static constexpr size_t bits = 64;
		typedef uint16_t Half;
		typedef uint32_t Word;
		typedef int32_t Sword;
		typedef uint64_t Xword;
		typedef int64_t Sxword;
		typedef uint64_t Addr;
		typedef uint64_t Off;
		typedef uint16_t SectionIndex;
		typedef uint32_t SymbolIndex;
	};

	enum ElfIdentification
	{
		EI_CLASS = 4,
		EI_DATA = 5,
		EI_OSABI = 7,
		EI_NIDENT = 16,
	};

	enum ElfDataType
	{
		ELFDATANONE = 0,
		ELFDATA2LSB = 1,
		ELFDATA2MSB = 2,
	};

	enum ElfPhdrType
	{
		PT_LOAD = 1,
		PT_DYNAMIC = 2,
	};

	enum ElfShdrType
	{
		SHT_PROGBITS = 1,
		SHT_SYMTAB = 2,
		SHT_STRTAB = 3,
		SHT_DYNSYM = 11,
	};

	enum ElfSymbolType
	{
		STT_FUNC = 2,
	};

	enum ElfDynamicTag
	{
		DT_PLTRELSZ = 2,
		DT_STRTAB = 5,
		DT_SYMTAB = 6,
		DT_RELA = 7,
		DT_RELASZ = 8,
		DT_RELAENT = 9,
		DT_INIT = 12,
		DT_FINI = 13,
		DT_REL = 17,
		DT_PLTREL = 20,
		DT_JMPREL = 23,
		DT_INIT_ARRAY = 25,
		DT_FINI_ARRAY = 26,
		DT_INIT_ARRAYSZ = 27,
		DT_FINI_ARRAYSZ = 28,
		DT_PREINIT_ARRAY = 32,
		DT_PREINIT_ARRAYSZ = 33,
		DT_MAX = 34,
	};

	enum ElfMachine
	{
		EM_NONE = 0, // No machine
		EM_M32 = 1, // AT&T WE 32100
		EM_SPARC = 2, // SPARC
		EM_386 = 3, // Intel 386
		EM_68K = 4, // Motorola 68000
		EM_88K = 5, // Motorola 88000
		EM_IAMCU = 6, // Intel MCU
		EM_860 = 7, // Intel 80860
		EM_MIPS = 8, // MIPS R3000
		EM_S370 = 9, // IBM System/370
		EM_MIPS_RS3_LE = 10, // MIPS RS3000 Little-endian
		EM_PARISC = 15, // Hewlett-Packard PA-RISC
		EM_VPP500 = 17, // Fujitsu VPP500
		EM_SPARC32PLUS = 18, // Enhanced instruction set SPARC
		EM_960 = 19, // Intel 80960
		EM_PPC = 20, // PowerPC
		EM_PPC64 = 21, // PowerPC64
		EM_S390 = 22, // IBM System/390
		EM_SPU = 23, // IBM SPU/SPC
		EM_V800 = 36, // NEC V800
		EM_FR20 = 37, // Fujitsu FR20
		EM_RH32 = 38, // TRW RH-32
		EM_RCE = 39, // Motorola RCE
		EM_ARM = 40, // ARM
		EM_ALPHA = 41, // DEC Alpha
		EM_SH = 42, // Hitachi SH
		EM_SPARCV9 = 43, // SPARC V9
		EM_TRICORE = 44, // Siemens TriCore
		EM_ARC = 45, // Argonaut RISC Core
		EM_H8_300 = 46, // Hitachi H8/300
		EM_H8_300H = 47, // Hitachi H8/300H
		EM_H8S = 48, // Hitachi H8S
		EM_H8_500 = 49, // Hitachi H8/500
		EM_IA_64 = 50, // Intel IA-64 processor architecture
		EM_MIPS_X = 51, // Stanford MIPS-X
		EM_COLDFIRE = 52, // Motorola ColdFire
		EM_68HC12 = 53, // Motorola M68HC12
		EM_MMA = 54, // Fujitsu MMA Multimedia Accelerator
		EM_PCP = 55, // Siemens PCP
		EM_NCPU = 56, // Sony nCPU embedded RISC processor
		EM_NDR1 = 57, // Denso NDR1 microprocessor
		EM_STARCORE = 58, // Motorola Star*Core processor
		EM_ME16 = 59, // Toyota ME16 processor
		EM_ST100 = 60, // STMicroelectronics ST100 processor
		EM_TINYJ = 61, // Advanced Logic Corp. TinyJ embedded processor family
		EM_X86_64 = 62, // AMD x86-64 architecture
		EM_PDSP = 63, // Sony DSP Processor
		EM_PDP10 = 64, // Digital Equipment Corp. PDP-10
		EM_PDP11 = 65, // Digital Equipment Corp. PDP-11
		EM_FX66 = 66, // Siemens FX66 microcontroller
		EM_ST9PLUS = 67, // STMicroelectronics ST9+ 8/16 bit microcontroller
		EM_ST7 = 68, // STMicroelectronics ST7 8-bit microcontroller
		EM_68HC16 = 69, // Motorola MC68HC16 Microcontroller
		EM_68HC11 = 70, // Motorola MC68HC11 Microcontroller
		EM_68HC08 = 71, // Motorola MC68HC08 Microcontroller
		EM_68HC05 = 72, // Motorola MC68HC05 Microcontroller
		EM_SVX = 73, // Silicon Graphics SVx
		EM_ST19 = 74, // STMicroelectronics ST19 8-bit microcontroller
		EM_VAX = 75, // Digital VAX
		EM_CRIS = 76, // Axis Communications 32-bit embedded processor
		EM_JAVELIN = 77, // Infineon Technologies 32-bit embedded processor
		EM_FIREPATH = 78, // Element 14 64-bit DSP Processor
		EM_ZSP = 79, // LSI Logic 16-bit DSP Processor
		EM_MMIX = 80, // Donald Knuth's educational 64-bit processor
		EM_HUANY = 81, // Harvard University machine-independent object files
		EM_PRISM = 82, // SiTera Prism
		EM_AVR = 83, // Atmel AVR 8-bit microcontroller
		EM_FR30 = 84, // Fujitsu FR30
		EM_D10V = 85, // Mitsubishi D10V
		EM_D30V = 86, // Mitsubishi D30V
		EM_V850 = 87, // NEC v850
		EM_M32R = 88, // Mitsubishi M32R
		EM_MN10300 = 89, // Matsushita MN10300
		EM_MN10200 = 90, // Matsushita MN10200
		EM_PJ = 91, // picoJava
		EM_OPENRISC = 92, // OpenRISC 32-bit embedded processor
		EM_ARC_COMPACT = 93, // ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)
		EM_XTENSA = 94, // Tensilica Xtensa Architecture
		EM_VIDEOCORE = 95, // Alphamosaic VideoCore processor
		EM_TMM_GPP = 96, // Thompson Multimedia General Purpose Processor
		EM_NS32K = 97, // National Semiconductor 32000 series
		EM_TPC = 98, // Tenor Network TPC processor
		EM_SNP1K = 99, // Trebia SNP 1000 processor
		EM_ST200 = 100, // STMicroelectronics (www.st.com) ST200
		EM_IP2K = 101, // Ubicom IP2xxx microcontroller family
		EM_MAX = 102, // MAX Processor
		EM_CR = 103, // National Semiconductor CompactRISC microprocessor
		EM_F2MC16 = 104, // Fujitsu F2MC16
		EM_MSP430 = 105, // Texas Instruments embedded microcontroller msp430
		EM_BLACKFIN = 106, // Analog Devices Blackfin (DSP) processor
		EM_SE_C33 = 107, // S1C33 Family of Seiko Epson processors
		EM_SEP = 108, // Sharp embedded microprocessor
		EM_ARCA = 109, // Arca RISC Microprocessor
		EM_UNICORE = 110, // Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
		EM_EXCESS = 111, // eXcess: 16/32/64-bit configurable embedded CPU
		EM_DXP = 112, // Icera Semiconductor Inc. Deep Execution Processor
		EM_ALTERA_NIOS2 = 113, // Altera Nios II soft-core processor
		EM_CRX = 114, // National Semiconductor CompactRISC CRX
		EM_XGATE = 115, // Motorola XGATE embedded processor
		EM_C166 = 116, // Infineon C16x/XC16x processor
		EM_M16C = 117, // Renesas M16C series microprocessors
		EM_DSPIC30F = 118, // Microchip Technology dsPIC30F Digital Signal Controller
		EM_CE = 119, // Freescale Communication Engine RISC core
		EM_M32C = 120, // Renesas M32C series microprocessors
		EM_TSK3000 = 131, // Altium TSK3000 core
		EM_RS08 = 132, // Freescale RS08 embedded processor
		EM_SHARC = 133, // Analog Devices SHARC family of 32-bit DSP processors
		EM_ECOG2 = 134, // Cyan Technology eCOG2 microprocessor
		EM_SCORE7 = 135, // Sunplus S+core7 RISC processor
		EM_DSP24 = 136, // New Japan Radio (NJR) 24-bit DSP Processor
		EM_VIDEOCORE3 = 137, // Broadcom VideoCore III processor
		EM_LATTICEMICO32 = 138, // RISC processor for Lattice FPGA architecture
		EM_SE_C17 = 139, // Seiko Epson C17 family
		EM_TI_C6000 = 140, // The Texas Instruments TMS320C6000 DSP family
		EM_TI_C2000 = 141, // The Texas Instruments TMS320C2000 DSP family
		EM_TI_C5500 = 142, // The Texas Instruments TMS320C55x DSP family
		EM_MMDSP_PLUS = 160, // STMicroelectronics 64bit VLIW Data Signal Processor
		EM_CYPRESS_M8C = 161, // Cypress M8C microprocessor
		EM_R32C = 162, // Renesas R32C series microprocessors
		EM_TRIMEDIA = 163, // NXP Semiconductors TriMedia architecture family
		EM_HEXAGON = 164, // Qualcomm Hexagon processor
		EM_8051 = 165, // Intel 8051 and variants
		EM_STXP7X = 166, // STMicroelectronics STxP7x family of configurable and extensible RISC processors
		EM_NDS32 = 167, // Andes Technology compact code size embedded RISC processor family
		EM_ECOG1 = 168, // Cyan Technology eCOG1X family
		EM_ECOG1X = 168, // Cyan Technology eCOG1X family
		EM_MAXQ30 = 169, // Dallas Semiconductor MAXQ30 Core Micro-controllers
		EM_XIMO16 = 170, // New Japan Radio (NJR) 16-bit DSP Processor
		EM_MANIK = 171, // M2000 Reconfigurable RISC Microprocessor
		EM_CRAYNV2 = 172, // Cray Inc. NV2 vector architecture
		EM_RX = 173, // Renesas RX family
		EM_METAG = 174, // Imagination Technologies META processor architecture
		EM_MCST_ELBRUS = 175, // MCST Elbrus general purpose hardware architecture
		EM_ECOG16 = 176, // Cyan Technology eCOG16 family
		EM_CR16 = 177, // National Semiconductor CompactRISC CR16 16-bit microprocessor
		EM_ETPU = 178, // Freescale Extended Time Processing Unit
		EM_SLE9X = 179, // Infineon Technologies SLE9X core
		EM_L10M = 180, // Intel L10M
		EM_K10M = 181, // Intel K10M
		EM_AARCH64 = 183, // ARM AArch64
		EM_AVR32 = 185, // Atmel Corporation 32-bit microprocessor family
		EM_STM8 = 186, // STMicroeletronics STM8 8-bit microcontroller
		EM_TILE64 = 187, // Tilera TILE64 multicore architecture family
		EM_TILEPRO = 188, // Tilera TILEPro multicore architecture family
		EM_CUDA = 190, // NVIDIA CUDA architecture
		EM_TILEGX = 191, // Tilera TILE-Gx multicore architecture family
		EM_CLOUDSHIELD = 192, // CloudShield architecture family
		EM_COREA_1ST = 193, // KIPO-KAIST Core-A 1st generation processor family
		EM_COREA_2ND = 194, // KIPO-KAIST Core-A 2nd generation processor family
		EM_ARC_COMPACT2 = 195, // Synopsys ARCompact V2
		EM_OPEN8 = 196, // Open8 8-bit RISC soft processor core
		EM_RL78 = 197, // Renesas RL78 family
		EM_VIDEOCORE5 = 198, // Broadcom VideoCore V processor
		EM_78KOR = 199, // Renesas 78KOR family
		EM_56800EX = 200, // Freescale 56800EX Digital Signal Controller (DSC)
		EM_BA1 = 201, // Beyond BA1 CPU architecture
		EM_BA2 = 202, // Beyond BA2 CPU architecture
		EM_XCORE = 203, // XMOS xCORE processor family
		EM_MCHP_PIC = 204, // Microchip 8-bit PIC(r) family
		EM_INTEL205 = 205, // Reserved by Intel
		EM_INTEL206 = 206, // Reserved by Intel
		EM_INTEL207 = 207, // Reserved by Intel
		EM_INTEL208 = 208, // Reserved by Intel
		EM_INTEL209 = 209, // Reserved by Intel
		EM_KM32 = 210, // KM211 KM32 32-bit processor
		EM_KMX32 = 211, // KM211 KMX32 32-bit processor
		EM_KMX16 = 212, // KM211 KMX16 16-bit processor
		EM_KMX8 = 213, // KM211 KMX8 8-bit processor
		EM_KVARC = 214, // KM211 KVARC processor
		EM_CDP = 215, // Paneve CDP architecture family
		EM_COGE = 216, // Cognitive Smart Memory Processor
		EM_COOL = 217, // iCelero CoolEngine
		EM_NORC = 218, // Nanoradio Optimized RISC
		EM_CSR_KALIMBA = 219, // CSR Kalimba architecture family
		EM_AMDGPU = 224, // AMD GPU architecture
		EM_WEBASSEMBLY = 0x4157, // WebAssembly architecture [temporary value])
	};
	
	enum ElfOsAbi
	{
		ELFOSABI_SYSV = 0,
		ELFOSABI_HPUX = 1,
		ELFOSABI_NETBSD = 2,
		ELFOSABI_GNU = 3,
		ELFOSABI_LINUX = ELFOSABI_GNU,
		ELFOSABI_SOLARIS = 6,
		ELFOSABI_AIX = 7,
		ELFOSABI_IRIX = 8,
		ELFOSABI_FREEBSD = 9,
		ELFOSABI_TRU64 = 10,
		ELFOSABI_MODESTO = 11,
		ELFOSABI_OPENBSD = 12,
		ELFOSABI_OPENVMS = 13,
		ELFOSABI_NSK = 14,
		ELFOSABI_AROS = 15,
		ELFOSABI_FENIXOS = 16,
		ELFOSABI_CLOUDABI = 17,
		ELFOSABI_OPENVOS = 18,
	};
	
	struct Segment
	{
		uint64_t vbegin;
		uint64_t vend;
		const uint8_t* fbegin;
	};

	template<typename Types>
	class ElfExecutable final : public Executable
	{
		typedef typename Types::Half half;
		typedef typename Types::Word word;
		typedef typename Types::Sword sword;
		typedef typename Types::Xword xword;
		typedef typename Types::Sxword sxword;
		typedef typename Types::Addr addr;
		typedef typename Types::Off off;
		typedef typename Types::SectionIndex seind;
		typedef typename Types::SymbolIndex syind;
		
		// structures
		struct Elf_Ehdr
		{
			uint8_t ident[EI_NIDENT];
			half type;
			half machine;
			word version;
			addr entry;
			off phoff;
			off shoff;
			word flags;
			half ehsize;
			half phentsize;
			half phnum;
			half shentsize;
			half shnum;
			half shstrndx;
		};
		
		// specialized below
		struct Elf_Phdr;
		struct Elf_Shdr;
		struct Elf_Sym;
		struct Elf_Dynamic;
		struct Elf_Rel;
		struct Elf_Rela;
		
		const Elf_Ehdr* header() const
		{
			return reinterpret_cast<const Elf_Ehdr*>(begin());
		}
		
		vector<Segment> segments;
		unordered_map<uint64_t, string> stubTargets;
		
	protected:
		virtual string doGetTargetTriple() const override
		{
			string arch;
			string os;
			bool isBigEndian = header()->ident[EI_DATA] == ELFDATA2MSB;
			bool is64Bits = is_same<Types, Elf64Types>::value;
			
			// This switch attempts to bridge the intersection of EM_* constants with LLVM supported architecture.
			switch (header()->machine)
			{
				case EM_AARCH64:
					arch = "aarch64";
					if (isBigEndian)
					{
						arch += "_be";
					}
					break;
				case EM_AVR: arch = "avr"; break;
				case EM_ARM:
					arch = "arm";
					if (isBigEndian)
					{
						arch += "eb";
					}
					break;
				case EM_HEXAGON: arch = "hexagon"; break;
				case EM_CSR_KALIMBA: arch = "kalimba"; break;
				case EM_MIPS:
					arch = "mips";
					if (is64Bits)
					{
						arch += "64";
					}
					if (!isBigEndian)
					{
						arch += "el";
					}
					break;
				case EM_MSP430: arch = "msp430"; break;
				case EM_PPC:
					assert(!is64Bits && isBigEndian);
					arch = "ppc";
					break;
				case EM_PPC64:
					assert(is64Bits);
					arch = "ppc64";
					if (!isBigEndian)
					{
						arch += "le";
					}
					break;
				case EM_SPARC:
					arch = "sparc";
					if (!isBigEndian)
					{
						arch += "el";
					}
					break;
				case EM_SPARCV9: arch = "sparcv9"; break;
				case EM_386:
					arch = "x86";
					if (is64Bits)
					{
						arch += "_64";
					}
					break;
				case EM_X86_64:
					assert(is64Bits);
					arch = "x86_64";
					break;
				case EM_XCORE: arch = "xcore"; break;
				default: arch = "unknown"; break;
			}
			
			// This one bridges EI_OSABI values to OS.
			switch (header()->ident[EI_OSABI])
			{
				case ELFOSABI_SYSV:
				case ELFOSABI_LINUX:
					os = "linux";
					break;
				case ELFOSABI_FREEBSD: os = "freebsd"; break;
				case ELFOSABI_NETBSD: os = "netbsd"; break;
				case ELFOSABI_OPENBSD: os = "openbsd"; break;
				case ELFOSABI_SOLARIS: os = "solaris"; break;
				case ELFOSABI_AIX: os = "aix"; break;
				default: os = "unknown";
			}
			
			return arch + "-unknown-" + os;
		}
		
	public:
		static ErrorOr<unique_ptr<ElfExecutable<Types>>> parse(const uint8_t* begin, const uint8_t* end);
		
		ElfExecutable(const uint8_t* begin, const uint8_t* end)
		: Executable(begin, end)
		{
			assert(end - begin >= sizeof(Elf_Ehdr));
		}
		
		virtual string getExecutableType() const override
		{
			union {
				short s;
				char c[2];
			} endianCheck = { .s = 0x0201 };
			
			char type[] = "ELF nn nE";
			snprintf(type, sizeof type, "ELF %02zu %cE", Types::bits, endianCheck.c[0] == 0x02 ? 'B' : 'L');
			return type;
		}
		
		virtual const uint8_t* map(uint64_t address) const override
		{
			for (auto iter = segments.rbegin(); iter != segments.rend(); iter++)
			{
				if (address >= iter->vbegin && address < iter->vend)
				{
					return iter->fbegin + (address - iter->vbegin);
				}
			}
			return nullptr;
		}
		
		virtual StubTargetQueryResult doGetStubTarget(uint64_t address, string& libraryName, string& into) const override
		{
			auto iter = stubTargets.find(address);
			if (iter != stubTargets.end())
			{
				into = iter->second;
				return ResolvedInFlatNamespace;
			}
			return Unresolved;
		}
	};

	template<>
	struct ElfExecutable<Elf32Types>::Elf_Phdr
	{
		word type;
		off offset;
		addr vaddr;
		addr paddr;
		word filesz;
		word memsz;
		word flags;
		word align;
	};

	template<>
	struct ElfExecutable<Elf64Types>::Elf_Phdr
	{
		word type;
		word flags;
		off offset;
		addr vaddr;
		addr paddr;
		xword filesz;
		xword memsz;
		xword align;
	};

	template<>
	struct ElfExecutable<Elf32Types>::Elf_Shdr
	{
		word name;
		word type;
		word flags;
		addr addr;
		off offset;
		word size;
		word link;
		word info;
		word addralign;
		word entsize;
	};

	template<>
	struct ElfExecutable<Elf64Types>::Elf_Shdr
	{
		word name;
		word type;
		xword flags;
		addr addr;
		off offset;
		xword size;
		word link;
		word info;
		xword addralign;
		xword entsize;
	};

	template<>
	struct ElfExecutable<Elf32Types>::Elf_Sym
	{
		word name;
		addr value;
		word size;
		unsigned char info;
		unsigned char other;
		half shndx;
	};

	template<>
	struct ElfExecutable<Elf64Types>::Elf_Sym
	{
		word name;
		unsigned char info;
		unsigned char other;
		half shndx;
		addr value;
		xword size;
	};

	template<>
	struct ElfExecutable<Elf32Types>::Elf_Dynamic
	{
		word tag;
		union {
			word value;
			addr address;
		};
	};

	template<>
	struct ElfExecutable<Elf64Types>::Elf_Dynamic
	{
		xword tag;
		union {
			xword value;
			addr address;
		};
	};

	template<>
	struct ElfExecutable<Elf32Types>::Elf_Rel
	{
		addr offset;
		word info;

		inline uint32_t symbol() const { return info >> 8; }
		inline uint8_t type() const { return info & 0xff; }
	};

	template<>
	struct ElfExecutable<Elf64Types>::Elf_Rel
	{
		addr offset;
		xword info;

		inline uint32_t symbol() const { return info >> 32; }
		inline uint32_t type() const { return info & 0xffffffff; }
	};

	template<>
	struct ElfExecutable<Elf32Types>::Elf_Rela : public ElfExecutable<Elf32Types>::Elf_Rel
	{
		sword addend;
	};

	template<>
	struct ElfExecutable<Elf64Types>::Elf_Rela : public ElfExecutable<Elf64Types>::Elf_Rel
	{
		sxword addend;
	};
	
	struct EntryPointArrayInfo
	{
		ElfDynamicTag locationTag;
		ElfDynamicTag sizeTag;
		string name;
	};

	template<typename Types>
	ErrorOr<unique_ptr<ElfExecutable<Types>>> ElfExecutable<Types>::parse(const uint8_t* begin, const uint8_t* end)
	{
		assert(end >= begin);
		
		using namespace std;
		auto executable = std::make_unique<ElfExecutable<Types>>(begin, end);
		
		deque<const Elf_Phdr*> dynamics;
		deque<const Elf_Shdr*> sections;
		deque<const Elf_Shdr*> symtabs;
		
		// Walk header, identify PT_LOAD and PT_DYNAMIC segments, sections, and symbol tables.
		bool loadAtZero = false;
		if (auto eh = bounded_cast<Elf_Ehdr>(begin, end, 0))
		{
			if (eh->phentsize == sizeof (Elf_Phdr))
			{
				for (const auto& ph : bounded_cast<Elf_Phdr>(begin, end, eh->phoff, eh->phnum))
				{
					if (ph.type == PT_LOAD)
					{
						unsigned long long endAddress;
						if (!__builtin_uaddll_overflow(ph.vaddr, ph.memsz, &endAddress))
						{
							auto fileLoc = bounded_cast<uint8_t>(begin, end, ph.offset, ph.filesz);
							if (fileLoc.begin() != nullptr)
							{
								Segment seg = { .vbegin = ph.vaddr, .vend = endAddress };
								seg.vbegin = ph.vaddr;
								seg.vend = endAddress;
								seg.fbegin = fileLoc.begin();
								executable->segments.push_back(seg);
								loadAtZero |= seg.vbegin == 0;
							}
						}
					}
					else if (ph.type == PT_DYNAMIC)
					{
						dynamics.push_back(&ph);
					}
				}
			}
			
			if (eh->shentsize == sizeof (Elf_Shdr))
			{
				for (const auto& sh : bounded_cast<Elf_Shdr>(begin, end, eh->shoff, eh->shnum))
				{
					sections.push_back(&sh);
					if (sh.type == SHT_SYMTAB)
					{
						symtabs.push_back(&sh);
					}
				}
			}
			
			if (eh->entry != 0 || loadAtZero)
			{
				executable->getSymbol(eh->entry).virtualAddress = eh->entry;
			}
		}
		
		// Walk dynamic segments.
		array<const Elf_Dynamic*, DT_MAX> dynEnt;
		dynEnt.fill(nullptr);
		
		for (const auto* dynHeader : dynamics)
		{
			size_t numEnts = dynHeader->filesz / sizeof (Elf_Dynamic);
			for (const auto& dyn : bounded_cast<Elf_Dynamic>(begin, end, dynHeader->offset, numEnts))
			{
				if (dyn.tag < DT_MAX)
				{
					dynEnt[dyn.tag] = &dyn;
				}
			}
		}
		
		EntryPointArrayInfo arrayInfo[] = {
			{DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, "preinit_"},
			{DT_INIT_ARRAY, DT_INIT_ARRAYSZ, "init_"},
			{DT_FINI_ARRAY, DT_FINI_ARRAYSZ, "fini_"},
		};
		for (const auto& arrayData : arrayInfo)
		{
			auto arrayLocation = dynEnt[arrayData.locationTag];
			auto arraySize = dynEnt[arrayData.sizeTag];
			if (arrayLocation != nullptr && arraySize != nullptr)
			{
				size_t counter = 0;
				const string& prefix = arrayData.name;
				for (addr entry : bounded_cast<addr>(begin, end, arrayLocation->address, arraySize->address))
				{
					auto& symInfo = executable->getSymbol(entry);
					symInfo.virtualAddress = entry;
					raw_string_ostream(symInfo.name) << prefix << counter;
					counter++;
				}
			}
		}
		
		pair<ElfDynamicTag, string> initFini[] = {
			{DT_INIT, "init"},
			{DT_FINI, "fini"}
		};
		for (const auto& pair : initFini)
		{
			auto location = dynEnt[pair.first];
			if (location != nullptr)
			{
				auto& symInfo = executable->getSymbol(location->address);
				symInfo.virtualAddress = location->address;
				symInfo.name = pair.second;
			}
		}
		
		if (dynEnt[DT_STRTAB] && dynEnt[DT_SYMTAB])
		if (const uint8_t* symtab = executable->map(dynEnt[DT_SYMTAB]->address))
		if (const uint8_t* strtab = executable->map(dynEnt[DT_STRTAB]->address))
		{
			// Check PLT relocations to put a name on relocated entries.
			if (dynEnt[DT_JMPREL] && dynEnt[DT_PLTRELSZ] && dynEnt[DT_PLTREL])
			if (const uint8_t* relocBase = executable->map(dynEnt[DT_JMPREL]->address))
			{
				ElfDynamicTag relType = static_cast<ElfDynamicTag>(dynEnt[DT_PLTREL]->value);
				if (relType == DT_REL || relType == DT_RELA)
				{
					// Fortunately, Elf_Rela is merely an extension of Elf_Rel and we can treat both as Elf_Rel as long
					// as we correctly increment the pointer.
					uint64_t relocSize = relType == DT_REL ? sizeof (Elf_Rel) : sizeof (Elf_Rela);
					for (uint64_t relocIter = 0; relocIter < dynEnt[DT_PLTRELSZ]->value; relocIter += relocSize)
					{
						if (const auto* reloc = bounded_cast<Elf_Rel>(relocBase, end, relocIter))
						if (const auto* symbol = bounded_cast<Elf_Sym>(symtab, end, sizeof (Elf_Sym) * reloc->symbol()))
						if (const char* nameBegin = bounded_cast<char>(strtab, end, symbol->name))
						{
							auto maxSize = static_cast<size_t>(end - reinterpret_cast<const uint8_t*>(nameBegin));
							const char* nameEnd = nameBegin + strnlen(nameBegin, maxSize);
							executable->stubTargets[reloc->offset] = string(nameBegin, nameEnd);
						}
					}
				}
			}
			
			// Also check RELA table. This is important especially on position-independent executables, which don't have
			// a PLT.
			if (dynEnt[DT_RELA] && dynEnt[DT_RELASZ] && dynEnt[DT_RELAENT] && dynEnt[DT_RELAENT]->value == sizeof (Elf_Rela))
			if (const uint8_t* relocBase = executable->map(dynEnt[DT_RELA]->address))
			{
				for (uint64_t relocIter = 0; relocIter < dynEnt[DT_RELASZ]->value; relocIter += sizeof (Elf_Rela))
				{
					if (const auto* reloc = bounded_cast<Elf_Rel>(relocBase, end, relocIter))
					if (const auto* symbol = bounded_cast<Elf_Sym>(symtab, end, sizeof (Elf_Sym) * reloc->symbol()))
					if (const char* nameBegin = bounded_cast<char>(strtab, end, symbol->name))
					{
						auto maxSize = static_cast<size_t>(end - reinterpret_cast<const uint8_t*>(nameBegin));
						const char* nameEnd = nameBegin + strnlen(nameBegin, maxSize);
						executable->stubTargets[reloc->offset] = string(nameBegin, nameEnd);
					}
				}
			}
		}
		
		// Walk symbol tables and identify function symbols.
		// This can override dynamic segment info, and it's fine.
		for (const auto* sth : symtabs)
		{
			if (sth->entsize != 0 && sth->entsize != sizeof (Elf_Sym))
			{
				continue;
			}
			
			const uint8_t* strtab = nullptr;
			if (sth->link != 0 && sth->link < sections.size())
			{
				auto strtabHeader = sections[sth->link];
				if (strtabHeader->type == SHT_STRTAB)
				{
					strtab = bounded_cast<uint8_t>(begin, end, strtabHeader->offset);
				}
			}
			
			size_t numEnts = sth->size / sizeof (Elf_Sym);
			for (const auto& sym : bounded_cast<Elf_Sym>(begin, end, sth->offset, numEnts))
			{
				// Exclude non-function symbols.
				if ((sym.info & 0xf) != STT_FUNC)
				{
					continue;
				}
				
				const char* nameBegin = nullptr;
				if (sym.name != 0)
				{
					nameBegin = bounded_cast<char>(strtab, end, sym.name);
				}
				
				const char* nameEnd = nameBegin;
				if (nameBegin != nullptr)
				{
					auto maxSize = static_cast<size_t>(reinterpret_cast<const char*>(end) - nameBegin);
					nameEnd = nameBegin + strnlen(nameBegin, maxSize);
				}
				
				auto& symInfo = executable->getSymbol(sym.value);
				symInfo.virtualAddress = sym.value;
				symInfo.name = string(nameBegin, nameEnd);
			}
		}
		
		// Figure out file offset for symbols, remove those that don't have one.
		for (auto entryPoint : executable->getVisibleEntryPoints())
		{
			if (executable->map(entryPoint) == nullptr)
			{
				executable->eraseSymbol(entryPoint);
			}
		}
		
		return move(executable);
	}
}

ElfExecutableFactory::ElfExecutableFactory()
: ExecutableFactory("elf", "ELF executable")
{
}

ErrorOr<unique_ptr<Executable>> ElfExecutableFactory::parse(const uint8_t* begin, const uint8_t* end)
{
	if (auto endianByte = bounded_cast<uint8_t>(begin, end, EI_DATA))
	{
		// We currently don't support non-native endianness (yet). At least return null if the ELF's endianness does not
		// match the host endianness instead of just crashing later or something.
		uint16_t hostEndianTest = (ELFDATA2MSB << 8) | ELFDATA2LSB;
		uint8_t hostEndian = *reinterpret_cast<uint8_t*>(&hostEndianTest);
		
		if (*endianByte != hostEndian)
		{
			return make_error_code(ExecutableParsingError::Elf_EndianMismatch);
		}
		
		if (auto classByte = bounded_cast<uint8_t>(begin, end, EI_CLASS))
		{
			switch (*classByte)
			{
				case 1: return ElfExecutable<Elf32Types>::parse(begin, end);
				case 2: return ElfExecutable<Elf64Types>::parse(begin, end);
				default: break;
			}
		}
	}
	
	return make_error_code(ExecutableParsingError::Elf_Corrupted);
}
