---
layout: page
permalink: /
---

# fcd

**fcd** is a burgeoning LLVM-based native program decompiler. Most of the code is licensed under the GNU GPLv3 license, though some parts, like the executable parsing code, is licensed under a less restrictive scheme.

Work on fcd started in April 2015, and it is nowhere near "really good" or "finished". However, it can already be useful for some reverse engineering tasks.

# What's cool about fcd

Fcd is built with the understanding that reverse engineering projects often have their own unique challenges. To that end, instead of trying to be anything and everything, fcd aims to implement a solid core set of functionality and provide extension points to allow reverse engineers to tailor fcd's behavior to their needs.

Currently, fcd works best with executables that follow the x86_64 System V ABI. Fcd supports ELF executables out-of-the-box, but also ships with [Python scripts that can be used as plug-ins][3] to parse Mach-O and PE executables. Additionally, fcd can [accept custom optimization passes][2], written in Python, that operate on LLVM IR to simplify programs. Finally, fcd uses Clang to accurately [parse header files][4] and get signatures for known functions.

Fcd provides a goto-free output by using [pattern-independent structuring][1].

  [1]: http://www.internetsociety.org/doc/no-more-gotos-decompilation-using-pattern-independent-control-flow-structuring-and-semantics
  [2]: {{ site.baseurl }}{% post_url 2016-02-21-csaw-wyvern %}
  [3]: {{ site.baseurl }}{% post_url 2016-11-12-csaw16 %}
  [4]: {{ site.baseurl }}{% post_url 2016-09-04-parsing-headers %}