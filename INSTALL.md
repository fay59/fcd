# Building fcd

Fcd compiles against the LLVM 4.0 release. It has been tested on macOS, and is at least known to build on Ubuntu. Automated test results are available on the [fcd-tests repository][2].

**Even LLVM dot releases can break API compatibility. For a smooth build experience, make sure that you have this exact version of LLVM.**

Please report build issues in the issue tracker.

## Building on Mac OS X

To build it with Xcode, you need to change the `CAPSTONE_DIR`, `LLVM_BIN_DIR`, `LLVM_BUILD_DIR`, `LLVM_SRC_DIR`, `CLANG_SRC_DIR` and `CLANG_BIN_DIR` user-defined variables to match the correct locations on your system.

By default, every `LLVM_*_DIR` and `CLANG_*_DIR` variables point to the same directory, and just reference `LLVM_BUILD_DIR` (such that changing that one only changes all the others). If you downloaded a pre-built LLVM distribution, you can use the decompressed root path directly.

* `CAPSTONE_DIR`: this should point to a directory in which can be found an "include/capstone/capstone.h" file. If you've installed capstone with Homebrew, this will be `/usr/local/Cellar/capstone/3.0.4`. Fcd is tested with Capstone 3.0.4.
* `LLVM_BIN_DIR`: this should point to a directory that contains a `/lib` directory with all the LLVM .a archives, and a `/bin` directory with the `clang` and `clang++` binaries. It is very important that *this* Clang version is linked against the same LLVM build that fcd does.
* `LLVM_BUILD_DIR`: this should point to a directory that contains a `/include` directory where LLVM outputs its build-specific headers.
* `LLVM_SRC_DIR`: this should point to a directory that contains a `/include` directory where the main LLVM headers reside. If you have a pre-built version of LLVM, this is the same as `LLVM_BUILD_DIR`.
* `CLANG_SRC_DIR` is the directory that contains a `/include` directory where the Clang includes reside. If you have a pre-built version of LLVM taken from the LLVM website, this is the same as `LLVM_SRC_DIR`.
* `CLANG_BIN_DIR` is the directory that contains a `/lib` director with all the Clang .a files. This is also the same as `LLVM_BIN_DIR` if you grab a build from the LLVM website.

With all that, the traditional Command+R should allow fcd to build and run.

Fcd can also be built with a mere developer command-line tools installation using `xcodebuild`. To build fcd using `xcodebuild`, you would move to the directory that contains `fcd.xcodeproj` and then run something like:

    $ xcodebuild -target fcd -configuration Release CAPSTONE_DIR="/usr/local/Cellar/capstone/3.0.4" LLVM_BUILD_DIR="../llvm-4.0"

## Building on Linux

Fcd builds on Linux using the provided top-level CMakeLists.txt file. It is known to build without issues on Ubuntu 16.10. (14.04 support, for [continuous integration purposes][3], is a work in progress.)

The following packages need to be installed:

* clang-4.0
* clang-4.0-dev
* cmake (version 3.2)
* cmake-data
* libz-dev (this can also be zlib1g-dev or lib32z1-dev)
* libcapstone3
* libcapstone-dev
* libedit-dev
* libstdc++-dev (version 6 or better)
* llvm-4.0
* llvm-4.0-dev
* python-dev (Python 2.7)

They should be available through your package manager. LLVM specifically is also available on the [LLVM apt repository][4].

Fcd is only tested with Clang. At any rate, fcd needs the Clang libraries to be present on the system, and needs to build specific files to LLVM IR using Clang. Might as well use it for everything else in the project.

# Special Files

The x86.emulator.cpp file has particular build rules. It is **not** meant to be directly built into fcd. Rather, it is built as an LLVM bitcode file with the Clang version that was included with your LLVM distribution, and then this bitcode file should be embedded into fcd as a data symbol. This is done using a platform-specific assembly file that uses the `.incbin` directive. The assembly template is called `incbin.[platform].tpl` and can be found in the cpu source directory.

  [1]: https://github.com/zneak/fcd/releases
  [2]: https://github.com/zneak/fcd-tests
  [3]: https://github.com/travis-ci/travis-ci/issues/5821
  [4]: http://apt.llvm.org/
