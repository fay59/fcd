Fcd compiles against the LLVM 3.7 release.

Fcd is currently only built on Mac OS X 10.10 with Xcode 7. To build, you need
to change the library path and the header search path to match your local LLVM
install. Since fcd development uses a debug build of LLVM, it has two LLVM
header directories; a release build only has one, so don't look for an
equivalent to the second one.

Even though it hasn't been attempted yet, a Linux build shouldn't be
particularly hard. Fcd should compile with the following Clang invocation, which
is trivially translated to a GCC invocation:

    clang++ `llvm-config --cxxflags` -std=c++14

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

Since **fcd/llvm-gvn-rewrite/MemorySSA.cpp** is taken from dberlin's
llvm-gvn-rewrite repository, it builds with different warning conventions. You
are encouraged to disable `-Wshorten-64-to-32` to build this file.

No other file needs different options.

The LLVM-related linker flags are obtained by running
`llvm-config --ldflags analysis codegen code passes`.

Please report build issues in the issue tracker.