# Building fcd

Fcd compiles against the LLVM 3.8.0 release. It has been tested (to the small
extent to which fcd is tested) on Mac OS X and Linux.

**Even LLVM dot releases can break API compatibility. For a smooth build
experience, make sure that you have this exact version of LLVM.**

Please report build issues in the issue tracker.

## Building on Mac OS X

Fcd is currently only built on Mac OS X 10.11 with Xcode 7. To build it with
Xcode, you need to change the `CAPSTONE_DIR`, `LLVM_BIN_DIR`, `LLVM_BUILD_DIR`
and `LLVM_SRC_DIR` user-defined variables to match the correct locations on
your system.

* `CAPSTONE_DIR`: this should point to a directory in which can be found an
  "include/capstone.h" file. Fcd is tested with Capstone 3.0.3.
* `LLVM_BIN_DIR`: this should point to a directory that contains a `/lib`
  directory with all the LLVM .a archives, and a `/bin` directory with the
  `clang` and `clang++` binaries. It is very important that *this* Clang version
  is linked against the same LLVM build that fcd does.
* `LLVM_BUILD_DIR`: this should point to a directory that contains a `/include`
  directory where LLVM outputs its build-specific headers.
* `LLVM_SRC_DIR`: this should point to a directory that contains a `/include`
  directory where the main LLVM headers reside. If you have a pre-built version
  of LLVM, this is the same as `LLVM_BUILD_DIR`.

With all that, the traditional Command+R should allow fcd to build and run.

**It's quite possible that the Linux Makefile will work with minor tweaks, but
it hasn't been tested and there are no plans to support this way of building on
Mac OS X in the foreseeable future.**

## Building on Linux

Fcd builds on Linux using the provided top-level Makefile. It has been tested on
Ubuntu 15.10. Prior to building, the following packages must be present:

* llvm-3.8
* clang-3.8
* libz-dev (this can also be zlib1g-dev or lib32z1-dev)
* libcapstone3
* libcapstone-dev
* libedit-dev
* python-dev (and Python 2.7)

They should be available through your package manager.

Fcd uses a small number of C++ features that are not available with the Ubuntu
15.10 stock compiler (gcc 5.2.1) but that are available with Clang 3.8. **Clang
is required to build CPU emulators into LLVM modules** (see "Special Files"), so
since it's guaranteed to be there, the Makefile builds fcd as a whole with it.
This could be revisited as new updates ship to Ubuntu; however, fcd will most
likely always build with the Clang version that matches the LLVM version that it
requires.

# Special Files

The x86.emulator.cpp file has particular build rules. It is **not** meant to be
directly built into fcd. Rather, it is built as a LLVM bitcode file with
the Clang version that was included with your LLVM distribution, and then this
bitcode file should be embedded into fcd as a data symbol. This is done using
a platform-specific assembly file that uses the `.incbin` directive. The
assembly template is called `incbin.[platform].tpl` and can be found in the cpu
source directory.

Since **fcd/llvm-gvn-rewrite/MemorySSA.cpp** is taken from LLVM's trunk, it
builds with different warning conventions. It is therefore highly probable that
you get warnings building it; they can be ignored as much as you trust LLVM.
