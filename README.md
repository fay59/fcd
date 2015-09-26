# fcd

**fcd** is a LLVM-based native program decompiler. Most of the code is licensed
under the GNU GPLv3 license, though some parts, like the executable parsing
code, is licensed under a less restrictive scheme.

It implements [pattern-independent structuring][1] to provide a goto-free output
(when decompilation succeeds).

It uses [interpiler][2] to create a code generator from an x86 emulator, making
it (usually) very easy to add new instructions to the decompilable set. It uses
[Capstone][4] for disassembly. Currently, fcd only supports x86_64, though it
would be very cool to add new front-ends.

To assist in reverse engineering, fcd can load Python scripts as LLVM passes to
clean up custom obfuscation schemes.

fcd is still a work in progress. You can contribute by finding ways to produce
a more readable output or by tackling one of the issues that deserves a branch.
Additionally, you can help by creating Makefiles or something else that will let
fcd build on a non-OS X system (the *INSTALL.md* file has more information on
that topic).

  [1]: http://www.internetsociety.org/doc/no-more-gotos-decompilation-using-pattern-independent-control-flow-structuring-and-semantics
  [2]: https://github.com/zneak/interpiler
  [3]: https://github.com/dberlin/llvm-gvn-rewrite
  [4]: https://github.com/aquynh/capstone

