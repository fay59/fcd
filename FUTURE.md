# Future Ideas

These are things that more or less need to happen at some point in the future,
tackled in order of interest (which may or may not be the order of usefulness).

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

May be related to previous point.
