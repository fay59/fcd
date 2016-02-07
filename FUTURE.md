# Future Ideas

These are things that more or less need to happen at some point in the future,
tackled in order of interest (which may or may not be the order of usefulness).
They are indiscriminately bug fixes or enhancements.

### Make tests

Fcd's tests are limited to the emulator code. While important, the pass logic is
at least as important and only has manual testing at the moment. Fuzz testing
might also be beneficial.

### Make pass pipeline customizable

The current pass pipeline is fixed and poorly fits programs that need custom
optimization passes to look good.

### Allow more back and forth between optimization and module generation

Some indirect calls or indirect jumps could be resolved at a later point in the
optimization pipeline but right now the program flow doesn't allow going back
to an earlier phase.

### Handle jump tables

May be related to previous point. For now, a function with an indirect jump fails
to decompile. (Indirect calls are handled mostly fine though.)

### Handle endless loops

A program with an endless loop will fail to decompile because the AstBackEnd
pass depends on the function's post-domination tree (which can't be created for
a function with an endless loop).
