# Future Ideas

These are things that more or less need to happen at some point in the future, tackled in order of interest (which may or may not be the order of usefulness). They are indiscriminately bug fixes or enhancements.

### Allow more back and forth between optimization and module generation

Some indirect calls or indirect jumps could be resolved at a later point in the optimization pipeline but right now the program flow doesn't allow going back to an earlier phase.

### Handle jump tables

May be related to previous point. For now, a function with an indirect jump fails to decompile. (Indirect calls are handled mostly fine though.)

### Handle global variables and values

Fcd currently poorly handles global variables and merely outputs loads to some given address. This is a relatively low hanging fruit.

### Allow symbols as input

Fcd accepts headers to figure out function arguments, but not symbol files. There are no plans to have built-inDWARF/PDB parsers, but it would be a good idea to have an interface that lets users plug that information into the decompilation pipeline.
