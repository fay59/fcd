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

Most decompilers try to isolate the useful behavior of instructions and encode
it as pseudo-C code. Fcd pushes the concept a notch further and uses LLVM's
optimization passes to aggressively transform decompiled code into something
simple. It does not attempt to closely match the assembly code or to provide an
easy way to navigate between the assembly code and the pseudo-C output.

A striking example is `__libc_csu_init`, that loops from `__init_array_start` to
`__init_array_end` and executes all the functions. This array is empty in many
programs and fcd will delete the loop entirely.

Fcd provides a goto-free output by using [pattern-independent structuring][1].

There is support for custom optimization passes written in Python, helping users
defeat custom obfuscation schemes.

  [1]: http://www.internetsociety.org/doc/no-more-gotos-decompilation-using-pattern-independent-control-flow-structuring-and-semantics