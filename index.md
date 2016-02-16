---
layout: page
permalink: /
---

# fcd

**fcd** is a burgeoning LLVM-based native program decompiler. Most of the code
is licensed under the GNU GPLv3 license, though some parts, like the executable
parsing code, is licensed under a less restrictive scheme.

Work on fcd started in April 2015, and it is nowhere near "really good" or
"finished". However, it can already be useful for some reverse engineering
tasks.

# What's cool about fcd

**fcd**, unlike most traditional decompilers, is an *optimizing decompiler*.
This means that it does not attempt to recreate source that closely matches the
executable's instructions: instead, it produces the simplest code it can for
what it sees. A striking example is `__libc_csu_init`, that loops over
`__init_array_entry` to `__init_array_end` and executes all the functions. In
many programs, `fcd` will detect that there is no element in the init array
and will omit the loop entirely.

To achieve this, **fcd** transforms programs into LLVM bitcode and simplifies it
using LLVM's optimization passes and a handful of custom-purpose passes. To
generate pseudo-C code, it uses [pattern-independent structuring][1] to provide
a goto-free output.

There is support for custom optimization passes written in Python, helping users
defeat custom obfuscation schemes.

  [1]: http://www.internetsociety.org/doc/no-more-gotos-decompilation-using-pattern-independent-control-flow-structuring-and-semantics