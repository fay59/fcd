//
//  ElfExecutableParser.h
//  x86Emulator
//
//  Created by Félix on 2015-07-21.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#ifndef ElfExecutableParser_h
#define ElfExecutableParser_h

#include "executable.h"

#include <cstdint>
#include <deque>
#include <unordered_map>
#include <unordered_set>

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
const T* ranged_cast(const uint8_t* begin, const uint8_t* end, size_t offset)
{
	unsigned long long max;
	if (__builtin_uaddll_overflow(offset, sizeof(T), &max) || end < begin || end - begin < max)
	{
		return nullptr;
	}
	
	return reinterpret_cast<const T*>(&begin[offset]);
}

template<typename T>
ptr_range<T> ranged_cast(const uint8_t* begin, const uint8_t* end, size_t offset, size_t count)
{
	unsigned long long max;
	if (__builtin_umulll_overflow(count, sizeof(T), &max) || __builtin_uaddll_overflow(offset, max, &max) || end < begin || end - begin < max)
	{
		return ptr_range<T>();
	}
	
	return ptr_range<T>(reinterpret_cast<const T*>(&begin[offset]), reinterpret_cast<const T*>(&begin[max]));
}

struct Elf32Types
{
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
	EI_NIDENT = 16,
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

struct Segment
{
	uint64_t vbegin;
	uint64_t vend;
	const uint8_t* fbegin;
};

template<typename Types>
class ElfExecutable : public Executable
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
	
	std::vector<Segment> segments;
	std::unordered_map<uint64_t, SymbolInfo> symInfo;
	
public:
	static std::unique_ptr<ElfExecutable<Types>> parse(const uint8_t* begin, const uint8_t* end);
	
	ElfExecutable(const uint8_t* begin, const uint8_t* end)
	: Executable(begin, end)
	{
	}
	
	virtual std::vector<uint64_t> getVisibleEntryPoints() const
	{
		std::vector<uint64_t> result;
		for (const auto& pair : symInfo)
		{
			result.push_back(pair.second.virtualAddress);
		}
		return result;
	}
	
	virtual const SymbolInfo* getInfo(uint64_t address)
	{
		auto iter = symInfo.find(address);
		if (iter != symInfo.end())
		{
			return &iter->second;
		}
		
		for (auto iter = segments.rbegin(); iter != segments.rend(); iter++)
		{
			if (address >= iter->vbegin && address < iter->vend)
			{
				SymbolInfo& info = symInfo[address];
				info.virtualAddress = address;
				info.memory = ranged_cast<uint8_t>(iter->fbegin, end(), address - iter->vbegin);
				return &info;
			}
		}
		
		return nullptr;
	}
	
	virtual std::string getStubTarget(uint64_t address) const
	{
		return "<fixme>";
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

std::unique_ptr<Executable> parseElfExecutable(const uint8_t* begin, const uint8_t* end)
{
	if (auto classByte = ranged_cast<uint8_t>(begin, end, EI_CLASS))
	{
		switch (*classByte)
		{
			case 1: return ElfExecutable<Elf32Types>::parse(begin, end);
			case 2: return ElfExecutable<Elf64Types>::parse(begin, end);
			default: break;
		}
	}
	return nullptr;
}

template<typename Types>
std::unique_ptr<ElfExecutable<Types>> ElfExecutable<Types>::parse(const uint8_t* begin, const uint8_t* end)
{
	using namespace std;
	auto executable = make_unique<ElfExecutable<Types>>(begin, end);
	
	deque<const Elf_Phdr*> dynamics;
	deque<const Elf_Shdr*> sections;
	deque<const Elf_Shdr*> symtabs;
	if (auto eh = ranged_cast<Elf_Ehdr>(begin, end, 0))
	{
		if (eh->phentsize == sizeof (Elf_Phdr))
		{
			for (const auto& ph : ranged_cast<Elf_Phdr>(begin, end, eh->phoff, eh->phnum))
			{
				if (ph.type == PT_LOAD)
				{
					unsigned long long endAddress;
					if (!__builtin_uaddll_overflow(ph.vaddr, ph.memsz, &endAddress))
					{
						auto fileLoc = ranged_cast<uint8_t>(begin, end, ph.offset, ph.filesz);
						if (fileLoc.begin() != nullptr)
						{
							Segment seg = { .vbegin = ph.vaddr, .vend = endAddress };
							seg.vbegin = ph.vaddr;
							seg.vend = endAddress;
							seg.fbegin = fileLoc.begin();
							executable->segments.push_back(seg);
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
			for (const auto& sh : ranged_cast<Elf_Shdr>(begin, end, eh->shoff, eh->shnum))
			{
				sections.push_back(&sh);
				if (sh.type == SHT_SYMTAB)
				{
					symtabs.push_back(&sh);
				}
			}
		}
		
		if (eh->entry != 0)
		{
			executable->symInfo[eh->entry].virtualAddress = eh->entry;
		}
	}
	
	// try to identify symbols through symtabs
	for (const auto* sth : symtabs)
	{
		if (sth->entsize != 0 && sth->entsize != sizeof (Elf_Sym))
		{
			continue;
		}
		
		const uint8_t* strtab = nullptr;
		if (sth->link != 0 && sth->link < sections.size() && sections[sth->link]->type == SHT_STRTAB)
		{
			strtab = ranged_cast<uint8_t>(begin, end, sth->offset);
		}
		
		size_t numEnts = sth->size / sizeof (Elf_Sym);
		for (const auto& sym : ranged_cast<Elf_Sym>(begin, end, sth->offset, numEnts))
		{
			const char* nameBegin = ranged_cast<char>(strtab, end, sym.name);
			const char* nameEnd = nameBegin;
			if (nameBegin != nullptr)
			{
				nameEnd = nameBegin + strnlen(nameBegin, reinterpret_cast<const char*>(end) - nameBegin);
			}
			
			auto& symInfo = executable->symInfo[sym.value];
			symInfo.virtualAddress = sym.value;
			symInfo.name = string(nameBegin, nameEnd);
		}
	}
	
	// figure out file offset for symbols
	auto symIter = executable->symInfo.begin();
	auto symEnd = executable->symInfo.end();
	while (symIter != symEnd)
	{
		bool found = false;
		uint64_t address = symIter->second.virtualAddress;
		for (auto iter = executable->segments.rbegin(); iter != executable->segments.rend(); iter++)
		{
			if (address >= iter->vbegin && address < iter->vend)
			{
				auto offset = address - iter->vbegin;
				symIter->second.memory = ranged_cast<uint8_t>(iter->fbegin, end, offset);
				found = true;
				break;
			}
		}
		
		if (found)
		{
			symIter++;
		}
		else
		{
			symIter = executable->symInfo.erase(symIter);
		}
	}
	
	return executable;
}

#endif /* ElfExecutableParser_h */
