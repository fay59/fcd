# fcd

**fcd** is a LLVM-based native program decompiler. Most of the code is licensed
under the GNU GPLv3 license, though some parts, like the executable parsing
code, is licensed under a less restrictive scheme.

It implements [pattern-independent structuring][1] to provide a goto-free output
(when decompilation succeeds).

It uses [interpiler][2] to create a code generator from an x86 emulator, making
it (usually) very easy to add new instructions to the decompilable set. It uses
[Capstone][4] for disassembly.

fcd is still a work in progress. You can contribute by finding ways to produce
a more readable output or by tackling one of the issues that deserves a branch.
Additionally, you can help by creating Makefiles or something else that will let
fcd build on a non-OS X system.

Currently, the code has dependencies on `__builtin` functions that should be
supported by both modern Clang and GCC (but not MSVC).

fcd uses a relatively old version of Daniel Berlin's MemorySSA utility, found in
[his GVN rewrite branch at dberlin/llvm-gvn-rewrite][3]. The version used is git
commit e80e9fd27680ab3566b06d9882fcbeb83fa53688. This could use some updating.

# This branch

The purpose of this branch is to refactor AST simplification into AST passes.
This should help create a higher-quality output.

  [1]: http://www.internetsociety.org/doc/no-more-gotos-decompilation-using-pattern-independent-control-flow-structuring-and-semantics
  [2]: https://github.com/zneak/interpiler
  [3]: https://github.com/dberlin/llvm-gvn-rewrite
  [4]: https://github.com/aquynh/capstone

