Fcd compiles against the LLVM 3.7 release.

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

Even though it hasn't been attempted yet, a Linux build shouldn't be
particularly hard. Fcd should compile with the following Clang invocation, which
is trivially translated to a GCC invocation:

    clang++ `llvm-config --cxxflags` -std=gnu++14

Fcd additionally needs to link against the Python framework. It is known to
compile against Python 2.7; Python 3 users may try at their own risk.

Fcd relies on `__builtin` functions for [checked arithmetic][1]. These functions
are supported in GCC 5 and later, but are not available to Microsoft's cl.exe
compiler. Additional porting efforts would be required to build fcd with cl.exe.
It is also quite possible that fcd depends on features that cl.exe does not
support yet.

The following Clang warning flags are enabled and observed as well as possible:

* `Wunreachable-code`
* `Wparentheses`
* `Wunused-function`
* `Wunused-variable`
* `Wunused-value`
* `Wempty-body`
* `Wconditional-uninitialized`
* `Wconstant-conversion`
* `Wint-conversion`
* `Wbool-conversion`
* `Wenum-conversion`
* `Wshorten-64-to-32`
* `Winvalid-offsetof`
* `Wnewline-eof`

Since **fcd/llvm-gvn-rewrite/MemorySSA.cpp** is taken from dberlin's
llvm-gvn-rewrite repository, it builds with different warning conventions. You
are encouraged to disable `-Wshorten-64-to-32` to build this file.

The x86.emulator.cpp file has particular build rules. It is **not** meant to be
directly built into fcd. Rather, it should be built as a LLVM bitcode file with
the Clang version that was included with your LLVM distribution, and then this
bitcode file should be embedded into fcd as a data symbol. The Xcode project
uses this custom build rule for *.emulator.cpp files:

	$LLVM_BIN_DIR/bin/clang++ -c -emit-llvm --std=gnu++14 --stdlib=libc++ \
		-isysroot $SDKROOT \
		-I$TOOLCHAIN_DIR/usr/include/c++/v1 \
		-iquote $CAPSTONE_DIR/include \
		-O3 -o $DERIVED_FILE_DIR/$INPUT_FILE_NAME.bc $INPUT_FILE_PATH

	export CPU=`basename $INPUT_FILE_NAME .emulator.cpp`
	export AS_PATH=$DERIVED_FILE_DIR/$INPUT_FILE_NAME.bc.s

	echo "\t.const_data" > $AS_PATH
	echo "\t.private_extern _fcd_emulator_start_$CPU" >> $AS_PATH
	echo "\t.private_extern _fcd_emulator_end_$CPU" >> $AS_PATH
	echo "_fcd_emulator_start_$CPU:" >> $AS_PATH
	echo "\t.incbin \"$INPUT_FILE_NAME.bc\"" >> $AS_PATH
	echo "_fcd_emulator_end_$CPU:" >> $AS_PATH

This makes a .bc file out of the .emulator.cpp file and copies it in an object
file.

No other C++ file in the fcd/ directory needs special treatment.

The LLVM-related linker flags are obtained by running
`llvm-config --ldflags analysis codegen code passes`.

Please report build issues in the issue tracker.

  [1]: http://stackoverflow.com/a/20956705/251153