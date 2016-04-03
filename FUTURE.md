# Future Ideas

These are things that more or less need to happen at some point in the future,
tackled in order of interest (which may or may not be the order of usefulness).
They are indiscriminately bug fixes or enhancements.

### Make tests

Fcd's tests are limited to the emulator code. While important, the pass logic is
at least as important and only has manual testing at the moment. Fuzz testing
might also be beneficial.

#### Stabilize output across runs

Currently, fcd may give a slightly different output when you run it multiple
times with the same parameters. The reasons haven't been studied in depth, but
using `unordered_map`s and `unordered_set`s over ASLR'd pointers certainly
doesn't help. This would probably need to change before we can even think about
serious tests.

### Allow more back and forth between optimization and module generation

Some indirect calls or indirect jumps could be resolved at a later point in the
optimization pipeline but right now the program flow doesn't allow going back
to an earlier phase.

### Handle jump tables

May be related to previous point. For now, a function with an indirect jump fails
to decompile. (Indirect calls are handled mostly fine though.)

### Handle external functions better

Right now, external functions have a tiny subset of their parameters hard-coded
into fcd, and attributes don't make the cut at all. The hard-coded list is
incomplete and annoying to maintain. Since some attributes (like `noreturn`)
have an impact on the control flow graph, this will sometimes lead to incorrect
output.

### Handle global variables

Fcd currently poorly handles global variables and merely outputs loads to some
given address. This is a relatively low hanging fruit.
