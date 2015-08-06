//
// executable.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is part of fcd. fcd as a whole is licensed under the terms
// of the GNU GPLv3 license, but specific parts (such as this one) are
// dual-licensed under the terms of a BSD-like license as well. You
// may use, modify and distribute this part of fcd under the terms of
// either license, at your choice. See the LICENSE file in this directory
// for details.
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

pair<const uint8_t*, const uint8_t*> Executable::mmap(const string& path) throw(std::system_error)
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
