//
// flat_binary.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
//

#ifndef fcd__executables_flat_binary_h
#define fcd__executables_flat_binary_h

#include "executable.h"

class FlatBinaryExecutableFactory final : public ExecutableFactory
{
public:
	FlatBinaryExecutableFactory();
	
	virtual llvm::ErrorOr<std::unique_ptr<Executable>> parse(const uint8_t* begin, const uint8_t* end) override;
};

#endif /* fcd__executables_flat_binary_h */
