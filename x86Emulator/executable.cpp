//
//  ExecutableParser.cpp
//  x86Emulator
//
//  Created by Félix on 2015-07-21.
//  Copyright © 2015 Félix Cloutier. All rights reserved.
//

#include "executable.h"
#include "elf_executable.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <system_error>
#include <unistd.h>

using namespace std;

namespace
{
	struct file_descriptor
	{
		int fd;
		
		file_descriptor(const string& path, int mode)
		{
			fd = open(path.c_str(), mode);
			if (fd < 0)
			{
				throw system_error(errno, system_category());
			}
		}
		
		operator int() { return fd; }
		~file_descriptor() { close(fd); }
	};
	
	const char elf_magic[4] = {0x7f, 'E', 'L', 'F'};
}

pair<const uint8_t*, const uint8_t*> Executable::mmap(const string& path) throw()
{
	file_descriptor fd(path, O_RDONLY);
	ssize_t length = lseek(fd, 0, SEEK_END);
	const uint8_t* data = (const uint8_t*)::mmap(nullptr, length, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == MAP_FAILED)
	{
		throw system_error(errno, system_category());
	}
	return make_pair(data, data + length);
}

std::unique_ptr<Executable> Executable::parse(const uint8_t* begin, const uint8_t* end)
{
	if (end < begin || end - begin < 4)
	{
		return nullptr;
	}
	
	if (memcmp(begin, elf_magic, sizeof elf_magic) == 0)
	{
		// ELF file
		return parseElfExecutable(begin, end);
	}
	
	return nullptr;
}
