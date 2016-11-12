---
layout: page
title: Manual
permalink: /help/
---

This page contains helpful information about fcd. As fcd is still very young,
its interfaces are likely to change in the future.

Currently, using fcd isn't too hard, but its most advanced features may require
some source digging.

<div class="warning">
<h1>A Word of Warning</h1>
<p>Fcd has not been tested on malware. While good coding practices are generally
being followed with respect to memory management, it has not been ruled out that
fcd or one of its dependencies could be vulnerable to attacks encoded in a
malicious executable. Use with caution on programs that you do not trust.</p>
<p>Additionally, even without any foul play, it's possible that fcd will crash,
hang, or try to eat all of your system's memory while running on some input. A
lot of work has gone into stability, but some more or less common patterns still
currently cause fcd to react ungracefully:</p>
<ul>
	<li>jump tables;</li>
	<li>(some) unbreakable loops;</li>
	<li>`if`s with complex conditions joined by short-circuiting ORs;</li>
	<li>unexpected uses of the address of stack-allocated objects.</li>
</ul>
<p>Finally, while fcd does generally good, it's a good idea to keep an eye open
for obvious patterns of misdecompilation. If a function's body is a single
`llvm.trap` statement, chances are that something went wrong.</p>
</div>

# Installing fcd

Fcd currently has no binary distribution and must be installed from source. It
is not known to build on Windows, though it should build if Clang is available
there. Build instructions are located in the [INSTALL.md][1] file in the source.

# Using fcd

Fcd uses LLVM's Command Line interface instead of `getopt` and friends. This
means that options are generally agnostic to whether you use `-o`, `--o`,
`-option` or `--option`; `-f foo`, `-f=foo`, `--f foo` or `--f=foo`, etc. By
convention, this document uses a single dash for one-letter options and two
dashes for so-called "long" options.

As outlined by `fcd --help`, the general usage is `fcd [options] <input>`. The
command also provides a good summary of the options presented here.

Currently, fcd is not particularly helpful on programs that don't have symbols
if you can't specify entry points yourself. This is because ELF executables tend
to call `__libc_start_main` from their entry point with the address of the
`main` function, and fcd isn't smart enough yet to follow function pointers.
If there's no symbol for the `main` function, fcd will probably miss it. (It
can still be specified separately as an entry point if you happen to know its
address; see more below.)

## Cheat Sheet

* Decompile a program:  
	`$ fcd program`
* Decompile a program with custom header files:  
	`$ fcd --header stdio.h program`
* Decompile a program using a custom header search path:  
	`$ fcd -I ./include -I ./include/x86_64-linux-gnu --header stdio.h program`
* Decompile a program using a custom executable parser:  
	`$ fcd -f scripts/mach-o.py macho-program`

## Supported executable types and architectures

Currently, fcd supports ELF executables and the **x86\_64** architecture. While
programs written with the x86 architecture will probably load too, this scenario
is currently not as much of a priority and output is expected to be inferior.
For best results, the executable should use the System V x86\_64 calling
convention.

In addition to ELF executables, fcd has a "flat binary" format. If you have a
binary in a format that is not supported (for instance, PE or Mach-O), you can
load it as a flat binary to a specified virtual address. This is often
sufficient for small and simple programs. The main downsides are that:

* you need to specify a load offset with `--flat-org`;
* imported symbol names cannot be guessed;
* the calling convention is not guessed;
* the entry point(s) are not guessed;
* you're screwed if the program has multiple, non-contiguous executable
	segments.

Finally, fcd lets you use a Python script that knows how to parse an executable.
This script needs to implement the following top-level members:

* an `init(data)` function, where `data` is a byte string containing the
	executable's data. The function is called before any other member of the
	module is used;
* an `executableType` variable that contains an arbitrary string identifying the
	type of the executable;
* an `entryPoints` global variable, typed as a list of `(virtualAddress, name)`
	tuples;
* a `getStubTarget(jumpTarget)` method that accepts the memory location that an
	import stub function jumps to, and returns a `(library name?, import name)`
	tuple (where the library name can be None if it is unknown, which is the
	case in executable formats that don't support two-level namespacing, like
	ELF);
* a `mapAddress(virtualAddress)` function that accepts a virtual address and
	returns the offset in `init`'s `data` parameter that contains the
	information at this address.

### Related options

* `--format`/`-f`: specifies the executable format. Currently supported values
	are:
	* `auto` (default): picks ELF if file starts with ELF magic, flat binary
		otherwise;
	* `elf`: forces ELF, does its best when the ELF format isn't respected;
	* `flat`: flat binary, does not attempt to parse executable at all;
	* `path/to/script.py`: use a Python script to parse executable.
* `--flat-org`: specifies the origin (virtual address) of the program when it
	is loaded as a flat binary. For instance, on Linux, this will often be
	`0x00400000`.
* `--cc`: specifies the default calling convention for functions. This is
	meant to form some kind of responder chain, eventually. Currently
	supported values are:
	* `auto`: autodetect. Asks each calling convention if they recognize the
		program and takes the first one that matches.
	* `any/any`: do best effort at figuring out parameters and return values
		using interprocedural analysis. This problem is fundamentally
		uncomputable, so results may vary.
	* `any/interactive`: ask for every function. Requires an underlying system
		calling convention.
	* `x86_64/sysv`: [System V x86\_64 calling convention][2], used on Linux and
		Mac OS X (for the x86\_64 architecture). **This is a so-called system
		calling convention** (and the only one currently implemented).

## Loading header files

Header files hint fcd about the parameters, return types and special attributes
of functions. If a program uses externel libraries and you have the headers for
it, using headers will systematically increase the quality of fcd's output.

Headers are loaded using the Clang parser.

Headers can be specified with the following options:

* `-I`: adds a directory to the header search path. Directories specified with
	the `-I` option are searched *before* system headers.
* `--header`: specifies the name of a header to include. For instance,
	`--header file.h` is the same as `#include "file.h"`. (As a reminder, quoted
	includes will search user paths first and system paths second.)

Under the Clang API, front-ends are responsible for setting up the include path.
To provide "reasonable defaults", fcd has a build script that extract Clang's
header search path and bakes it into the executable. Therefore, if you don't
specify any `-I` parameter, fcd will still look for headers in your Clang
installation's default search path.

If you know about a function in the executable, you can include its signature in
the header file as well. Fcd will assume that the function in the executable has
the same signature as the one you use in the header file. The prototype must be
followed with the `FCD_ADDRESS(address)` pseudo-attribute, where `address` is a
**numeric literal** that represents the function's virtual address in the
executable. For instance, assuming a program where `main` lives at 0x040045e,
you could pass a header that contains the following to fcd:

    int main(int argc, const char** argv) FCD_ADDRESS(0x040045e);

Functions annotated with `FCD_ADDRESS` are assumed to be entry points and will
be decompiled by fcd (unless you are running in partial mode).

## Entry points and level of decompilation

Fcd still being somewhat slow, it might not always be worth it to decompile the
whole program you're interested with. For this reason, it is possible to ask for
partial (or exclusive) disassembly to limit how much work fcd tries to do. When
doing so, it is necessary to specify the virtual address of the functions that
need to be decompiled.

### Related options

* `--other-entry`/`-e`: specify the virtual address of a function to decompile.
	Can be used multiple times.
* `--partial`/`-p`: partial decompilation. Produce output only for the functions
	specified by `--other-entry` values and their call graph. Use `--partial`
	twice to **only** decompile the functions specified by `--other-entry` and
	not their call graph.
* `--module-out`/`-n`: stop after transforming the executable into a LLVM
	module, and dump that module to `stdout`. Mostly useful to experiment with
	passes when you don't want to spend most of your time waiting on the
	translation process.
* `--module-in`/`-m`: the `<input program>` parameter is the path to a LLVM
	module previously saved with `--module-out`. Users of this option need to
	specify a calling convention, since it is normally guessed from the
	executable file.
* `--opt`/`-O`: insert a specific optimization pass in the middle of the pass
	pipeline. The optimization pass must either be the name of a pass included
	in the linked LLVM installation or a path to a `.py` file implementing a
	pass.

## Using custom passes

Fcd can load Python scripts as optimization passes for custom jobs. The script
must supply either a `runOnModule` global function or a `runOnFunction` global
function (but not both). It may also specify a `passName` global variable for
debugging convenience.

The Python bindings that fcd use are tailored from the LLVM C API in a very
mechanical way. *These bindings are subject to change*: firstly because LLVM's
API tends to change between releases and the plan is to stay up-to-date with
stable LLVM releases, and secondly because absolutely no intelligent design has
gone into these bindings beyond the automatic translation of header files yet.
These bindings merely attach methods on types based on the name of the function
and the type of the first parameter: for instance,
`LLVMGetFirstBasicBlock(LLVMValueRef)` is translated as a `GetFirstBasicBlock`
method on the `Value` Python type. This isn't so bad, but it can get a little
confusing with the `IsA*` methods: `LLVMIsAConstantExpr(LLVMValueRef)` creates
a `IsAConstantExpr` method on `Value`, which returns a handle to a constant
expression if the `Value` object was a `ConstantExpr`. This is just one thing on
the long laundry list of things to do for fcd in the future.

To explore the API, you are encouraged to familiarize yourself with the LLVM C
API. Another simple thing to do could be to [drop into a Python REPL][3] from
`runOnFunction` to call `dir` and `help` on everything to see where the pieces
fall.

  [1]: https://github.com/zneak/fcd/blob/master/INSTALL.md
  [2]: http://www.x86-64.org/documentation/abi.pdf
  [3]: http://stackoverflow.com/a/1396386/251153