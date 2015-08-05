# fcd

**fcd** is a LLVM-based native program decompiler. It implements
[pattern-independent structuring][1] to provide a goto-free output (when
decompilation succeeds).

It uses [interpiler][2] to create a code generator from an x86 emulator, making
it (usually) very easy to add new instructions to the decompilable set.

fcd is still a work in progress. You can contribute by finding ways to produce
a more readable output or by tackling one of the issues that deserves a branch.

**This branch** exists for the purpose of replacing the `StructurizeCFG` pass
with a pass that merely transforms loops into single-entry, single-exit regions.
`StructurizeCFG` does what we need, but it also structurizes everything else and
creates too many PHI nodes to afford us a readable output.

  [1]: http://www.internetsociety.org/doc/no-more-gotos-decompilation-using-pattern-independent-control-flow-structuring-and-semantics
  [2]: https://github.com/zneak/interpiler