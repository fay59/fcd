# Contributing to fcd

fcd would heavily benefit from contributors.

## Reporting issues

At this point, it is **very well known** that fcd has lots of issues. Because of this,
pull requests and fixes are much, much more welcome than issue reports. If you do wish to
report an issue, please respect the following guidelines. An issue that does not follow
these guidelines will be notified as such, and may be closed after 24 hours if it is not
amended (or right away, if these guidelines prescribe it).

*	**Issues about instructions that cannot be decompiled will be closed without
	consideration.** See below for how to fix it yourself and submit a PR.
*	If the issue is with how fcd builds on your platform, I'll be happy to help. Please
	join your build script and include the full build output up to the errors.
*	If the issue is about decompiled output correctness, other decompiling errors, and
	things that you generally feel should not be happening, please join the **smallest**
	code you can that will reproduce the issue. This can be either a C file or a NASM file
	that will build to a flat binary. If fcd crashes or outputs an error, the issue must
	be named after that error. If another issue with the same name exists, please do not
	open a new one (you're welcome to submit your test case to it though).
*	Issues about general project policies are welcome.
*	Issues that discuss future features that require design changes are welcome (as long
	as you are willing to program these changes).

## Pull requests

Pull requests are very, very welcome. Just note that the following conventions have to be
respected:

*	Files are UTF-8, use LF as line terminators, and must be indented with tabs.
*	There will be no breakdown if you don't fit things within 120 columns, but please try
	to anyway. Broken-up lines should be indented **one more tab** than the previous line.
*	File names must be lower\_snake\_case and relatively short.
*	Classes are `PascalCased`, methods and fields are `camelCased`. In case of a conflict
	between a field name and a method name, **append** a `_` to the field name. Local
	variables and parameters are also `camelCased`. Preprocessor macros are `UPPER_CASE`.
*	Control statements (`if`, `else`, `while`, `for`, etc) must *almost always* be
	followed by a block. The only exception is for cascades of `if` statements using
	declarations as conditions, since this otherwise tends to create [pyramids of doom][1].
*	Using declarations as conditions in control structures is encouraged. Multiple `if`
	statements declaring variables do not have to be followed by a block and must not be
	indented. For instance, this is encouraged (as long as `else` statements are not
	required):

```
if (Foo* foo = getFoo())
if (Bar* bar = foo->getBar())
if (Frob* frob = bar->getFrob())
{
	// stuff here
}
```

*	Unless it causes dependency problems, `#include` statements should be ordered to
	include user headers first, LLVM headers second, and system headers last. Each should
	be in alphabetical order.
*	In general, a PR that includes a new library will need to make a clear demonstration
	of the benefits.
*	If your changes cause warnings on my machine, you'll be asked to fix them. (The
	warning flags are outlined in INSTALL.md.)
*	This is list just what I could think of and there may be other things.

Existing code does not always match these, but this is what is expected for current and
future code. Any PR to fix any violation of this in the current source is very welcome.

There are currently no automated tests for the decompiler itself, but a PR that would
include some would be welcome.

### PR for something big

If you want to make something that will require design changes, please discuss it in an
issue.

### PR for a new instruction

Support for new instructions should be implemented in the emulator and test cases should
be implemented in the `x86_emu_tests` project to cover at least the normal case and a few
specific cases for flags (but feel free to be more extensive than this).

  [1]: https://en.wikipedia.org/wiki/Pyramid_of_doom_(programming)