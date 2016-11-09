# fcd

**fcd** is a LLVM-based native program optimizing decompiler, released under the
GPLv3 license.

It implements [pattern-independent structuring][1] to provide a goto-free output
(when decompilation succeeds).

Fcd currently only supports x86_64 programs. It implements a (partial) x86
emulator in C++, with one function per instruction, and compiles it to LLVM
bytecode. To produce its output, fcd disassembles the target program and inlines
each instruction's function's bytecode into a result function. This allows
painless extension of the supported instruction set and powerful testing.
Instructions that aren't implemented by the emulator are emitted as assembly
statements; but since fcd uses [Capstone][2], it can at least tell which
registers the instruction reads and writes and still produce useful code when
that happens.

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
a more readable output, by making it more reliable, or by tackling an issue
outlined in the `FUTURE.md` file.

  [1]: http://www.internetsociety.org/doc/no-more-gotos-decompilation-using-pattern-independent-control-flow-structuring-and-semantics
  [2]: https://github.com/aquynh/capstone
