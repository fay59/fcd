# fcd

[![Travis build status][3]][7]

**Fcd** is an LLVM-based native program optimizing decompiler, released under an LLVM-style license. It started as a bachelor's degree senior project and carries forward its initial development philosophy of getting results fast. As such, it was architectured to have low coupling between distinct decompilation phases and to be highly hackable.

Fcd uses a [unique technique][4] to reliably translate machine code to LLVM IR. Currently, it only supports x86_64. Disassembly uses [Capstone][2]. It implements [pattern-independent structuring][1] to provide a goto-free output.

Fcd allows you to [write custom optimization passes][6] to help solve odd jobs. It also [accepts header files][5] to discover function prototypes.

  [1]: http://www.internetsociety.org/doc/no-more-gotos-decompilation-using-pattern-independent-control-flow-structuring-and-semantics
  [2]: https://github.com/aquynh/capstone
  [3]: https://travis-ci.org/zneak/fcd.svg?branch=master
  [4]: http://zneak.github.io/fcd/2016/02/16/lifting-x86-code.html
  [5]: http://zneak.github.io/fcd/2016/09/04/parsing-headers.html
  [6]: http://zneak.github.io/fcd/2016/02/21/csaw-wyvern.html
  [7]: https://travis-ci.org/zneak/fcd
