---
layout: post
title:  "Lifting x86 code into LLVM bitcode"
date:   2016-02-16 14:01:26 -0500
---

At the risk of stating the obvious, the goal of a decompiler is to take binary
code and turn it into (more or less) readable pseudo-source. Decompilers rarely
perform a lot of work on the machine code representation itself: instead, the
current state of the art, as discovered by Michael Van Emmerick in 2007, is to
lift the machine code into an easily-analyzable [*static single assingment*][1]
representation, perform constant propagation and dead code elimination, and then
turn that into readable source. The process of taking machine code and turning
it into an SSA representation is called "lifting", probably as it is the
opposite of the more formally identified "lowering" phase of compilers where the
SSA form is transformed into machine code.

This is amusingly similar to how compilers work, and as it turns out, 2015 saw
no shortage of compiler back-ends, as [even GCC entered the fray][3]. When Van
Emmerick wrote his thesis, he warned that LLVM wasn't up to the challenges of
decompilation. Being the stubborn undergrad senior I was in 2015, I thought that
I might give it a try anyway. (At this time, it might be worth stating that fcd
started as my undergrad senior project.)

LLVM was seductive because I knew that if I could accurately represent the
effects of x86 instructions as LLVM IR, I could instantly benefit from a host of
powerful optimizations that I could never write myself, let alone in the short
time frame after which my project would be graded.

However, just lifting machine code into an intermediate representation is a
daunting task. The Trail of Bits organization has a framework called
[MC-Semantics][2] whose job is to do just that, and they've been working on it
since 2014. Closer to my situation, François Chagnon attempted a similar senior
project two years prior, and he chose to implement about 30 instructions (plus
every `j*`, `set*` and `cmov*` variations) of the ~1300 that x86 processors
understand, and he opted to go with his own, simpler IR instead of LLVM. In
other words, this is a lot of work.

Since I wanted to stay up-to-date with LLVM, MC-Semantics was a no-go (as it is
stuck with LLVM 3.5), so I would have to lift IR myself. Fortunately, I had
(what I think is) a pretty neat idea: let Clang do it.

When you start using LLVM, a common trick to familiarize yourself with the
framework and its IR is to write a small program with the desired IR feature in
C, compile it to LLVM IR with Clang, and see how it works. With a little
ingenuity, you can extend on the concept and have Clang write IR for *anything
that you can express in C*. In other words, if you can write an emulator in C,
Clang will happily emit IR templates for all of your instructions, without you
even doing as much as declaring an `IRBuilder<>`.

And this is [exactly what I did][4] (except that I used C++). I wrote a bunch of
functions that accept a flag structure pointer, a register structure pointer,
and a [Capstone][5] instruction structure. The functions modify memory, flags
and registers in accordance to the instruction's behavior. This emulator is
compiled as a bitcode file, and the bitcode file is embedded into fcd. Each
function includes a lot of code that will quickly turn dead, since there are
different code paths for loading values from registers or from memory, for
instance, even though just one of these is required for any specific
instruction. Then, LLVM's `CloneAndPruneIntoFromInst` function takes that
implementation, a register structure pointer, a flag pointer and a constant
Capstone instruction structure, and constant propagation and control flow graph
simplifying will melt that useless code away like it was never there.

Of course, you can't describe everything in C++. For instance, you can't really
write a C++ function that will inline as a jump. For these, fcd defines
"intrinsic" functions that are replaced with short, hand-written IR snippets at
inlining time.

There are big advantages to this method. First, it's usually very easy to add
new instructions and maintain existing ones, since you only need to write a C++
function that describes their side effects (instead of a C++ function that
writes IR that describes their side effects). Second, it can easily be tested by
running machine code and then running the emulator and making sure that they
both did the same thing (in fact, it can so easily be tested that I [found an
error in Intel's documentation][7]). When things go wrong, you can drop into the
debugger and fix the problem, which is dead simple compared to debugging where
your IR generating code went wrong. Third, code templates are inherently
modular, so it could be relatively simple to add other machine code front-ends.

Still, it's not perfect either. Fcd wastes a *lot* of time reading in dead code
and eliminating it. Additionally, for simplicity, the x86 code assumes that
everything is a 64-bit integer. While it doesn't lead to incorrect output, it
certainly leads to murkier output, since LLVM often can't just narrow integers
down and the code becomes full of casts. This is especially punishing on 32-bit
code.

Another problem is that some conditions can become quite obtuse: for instance,
`jg` ("jump if greater than") tests that the zero flag isn't set and that the
sign flag is equal to the overflow flag. The instruction is usually used after
`cmp` or `sub`, but because of the code they use to set flags, without
post-processing, conditions would usually end up looking like:

	c = b - a;
	if ((c >> 63) == 1 && ((b ^ c) & (b ^ a) > 9223372036854775807))

which is arguably less readable than:

    if (b > a)

There is post-processing code to make it look prettier, and it often works, but
the current output is still often not ideal.

Other problems have relatively simple solutions that have simply not been
implemented yet. For instance, the time wasted with dead code could be
drastically reduced if functions like `x86_read_source_operand` were implemented
as intrinsics instead, since they cause the bulk of the code bloat.

But even with this, as a single developer working on a decompiler, I find this
shortcut to be *totally worth it*.

  [1]: https://fr.wikipedia.org/wiki/Static_single_assignment_form
  [2]: https://github.com/trailofbits/mcsema
  [3]: https://gcc.gnu.org/wiki/JIT
  [4]: https://github.com/zneak/fcd/blob/c0ec58e7f59262e2933436f482b6680fca936b3e/fcd/cpu/x86.emulator.cpp
  [5]: http://www.capstone-engine.org/
  [6]: http://llvm.org/docs/doxygen/html/namespacellvm.html#ae1a030c9a70b99fced16cc726e1ef9f9
  [7]: http://stackoverflow.com/q/29901622/251153
  