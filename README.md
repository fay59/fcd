# fcd

**fcd** is a LLVM-based native program optimizing decompiler. Most of the code
is licensed under the GNU GPLv3 license, though some parts, like the executable
parsing code, are licensed under a less restrictive scheme.

It implements [pattern-independent structuring][1] to provide a goto-free output
(when decompilation succeeds).

Fcd currently only supports x86_64 programs. It implements a (partial) x86
emulator in C++, with one function per instruction, and compiles it to LLVM
bytecode. To produce its output, it disassembles the program and inlines each
instruction's function's bytecode into a result function. This allows painless
extension of the supported instruction set and powerful testing.

Disassembly uses [Capstone][2].

## An optimizing decompiler

Fcd's goal is not to produce fidel output of the disassembly. Rather, it aims to
produce code that looks more natural and more readable. This is especially
valuable in the case of obfuscated executables, where fidel output is next to
useless.

However, in some conditions, it may make it harder to detect vulnerabilities.
This means that fcd is usually more helpful for reverse engineering tasks than
for exploitation tasks.

To assist in reverse engineering, fcd can load Python scripts as LLVM
optimization passes to clean up custom obfuscation schemes.

Fcd is still a work in progress. You can contribute by finding ways to produce
a more readable output or by tackling one of the issues that deserves a branch.
Additionally, you can help by creating Makefiles or something else that will let
fcd build on a non-OS X system (the *INSTALL.md* file has more information on
that topic).

  [1]: http://www.internetsociety.org/doc/no-more-gotos-decompilation-using-pattern-independent-control-flow-structuring-and-semantics
  [2]: https://github.com/aquynh/capstone
