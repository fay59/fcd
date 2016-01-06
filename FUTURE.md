# Future Ideas

These are things that more or less need to happen at some point in the future,
tackled in order of interest (which may or may not be the order of usefulness).

### Make pass pipeline customizable

The current pass pipeline is fixed and poorly fits programs that need custom
optimization passes to look good.

### Get rid of interpiler dependency

Interpiler is ultimately a piece of middleware borne out of my ignorance. Fcd
could simply load in an emulator module and use `CloneFunctionInto` to generate
the disassembly module. It would definitely be worth it to look into
`CloneAndPruneFunctionInto`, as it performs some amount of constant propagation
and dead code elimination on the fly, resulting in less copying (which is
definitely something that hurts right now).

### Allow more back and forth between optimization and module generation

Some indirect calls or indirect jumps could be resolved at a later point in the
optimization pipeline but right now the program flow doesn't allow going back
to an earlier phase.

### Handle jump tables

May be related to previous point.
