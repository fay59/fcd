# fcd

**fcd** is a LLVM-based native program decompiler. It implements
[pattern-independent structuring][1] to provide a goto-free output (when
decompilation succeeds).

It uses [interpiler][2] to create a code generator from an x86 emulator, making
it (usually) very easy to add new instructions to the decompilable set.

fcd is still a work in progress. You can contribute by finding ways to produce
a more readable output or by tackling one of the issues that deserves a branch.
Additionally, you can help by creating Makefiles or something else that will let
fcd build on a non-OS X system.

Currently, the code has dependencies on `__builtin` functions that should be
supported by both modern Clang and GCC (but not MSVC).

fcd uses a relatively old version of Daniel Berlin's MemorySSA utility, found in
his GVN rewrite branch. The version used is git commit e7a8826a52bba231c7e60323a991b00deab915b2.
This could use some updating.

  [1]: http://www.internetsociety.org/doc/no-more-gotos-decompilation-using-pattern-independent-control-flow-structuring-and-semantics
  [2]: https://github.com/zneak/interpiler
  [3]: https://github.com/dberlin/llvm-gvn-rewrite