---
layout: post
title:  "Parsing headers for fun and profit"
---

One of the many challenges of decompiling programs is figuring out the parameters of functions that don't have a visible body. There are two main situations in which this can happen:

1. the function is called indirectly;
2. the function immediately jumps indirectly to somewhere else.

Of note, dynamic linker stubs create a lot of functions that immediately jump indirectly to somewhere else. Now, the great thing about dynamic linker stubs is that they often reference the name of an external function to call, and it's quite possible that headers for the library are available.

# Dynamic linkage primer

Since dynamic linkers are complicated beasts, I have no intention of diving very deep into their inner workings. However, for the sake of this post, it's useful to put out some basics about linkage (specifically targeting on x86_64 Linux ELF executables using `ld.so`). The basic idea is that when you pull in a function from a shared object in your program, the compiler creates a stub function. For instance:

	0000000000400480 <puts@plt>:
	  400480:	ff 25 a2 08 20 00    	jmp    QWORD PTR [rip+0x2008a2]
	  400486:	68 00 00 00 00       	push   0x5
	  40048b:	e9 e0 ff ff ff       	jmp    400470

This function is what your program actually calls when it tries to call `puts`. Here, `plt` stands for *Procedure Linkage Table*, and the address `QWORD PTR [rip+0x2008a2]` points right into it. On a call to `puts`, execution is transferred to the function pointed to by this entry in the PLT.

To save time on startup, the PLT is populated lazily. Initially, the entry at `QWORD PTR [rip+0x2008a2]` actually points right back to the following instruction. This means that the first time that you call `puts`, the rest of the stub is executed. We can interpret it as the pseudo-function call `0x400470(0x5)`. This calls into `ld.so` to read dynamic linkage metadata and get the name of the function that stub #5 refers to (which is "puts"). Then, it iterates dynamic libraries in order, until it finds a function of that name. `Ld.so` then writes back this address in the PLT and transfers execution to it. That way, the next time you call `puts`, you won't need to look it up again.

Of course, this is interesting because anyone can read out the dynamic linkage metadata, fcd included. This is how fcd figures out the name of imported functions.

# Just put a compiler in your decompiler

Unfortunately, in most cases, the function name doesn't say a lot. For instance, just "exit" doesn't say that the function accepts an integer and does not return. And since the function's body is in a different library, it's probably not possible (or at least, not practical) to get the implementation of that function.

Up until recently, fcd had a hard-coded list of approximately 50 glibc functions with their number of parameters, whether they returned a value, and if they were variadic (though that last property wasn't, and still isn't, put to great use). The parameter and return information did not include actual types. I added entries to it as I ran in programs that used new functions. Some functions, too, aren't part of the public API, but are just the result of macro expansion. For instance, on Linux, programs don't use `putc`; they use `_IO_putc`. Not only does this approach scale poorly, it doesn't port to additional platforms very easily.

Fortunately, there is an authoritative source of functions on almost every system out there: header files. We could solve this problem rather elegantly, and allow extensibility, by parsing .h files and using the information to determine function parameters.

As it turns out, fcd already links against LLVM and requires Clang to [lift machine code to LLVM IR][1]. Being that it's *this close* to link against Clang, it's not a huge step to take. It's also extremely convenient, because Clang is the only compiler (to my knowledge) that will happily parse Linux, Darwin (iOS, macOS) and Windows headers, making it a true one-stop shop. Even though fcd only supports ELF executables at the moment, it's great that Clang will not be a limitation in the foreseeable future.

The great thing about Clang, of course, is that it's an *actual* compiler. This solution is not some half-working, in-house C parser that explodes at the slightest hint of a macro: it's an industrial-grade and proven compiler that actually knows what it's doing.

Initially, I tried to integrate Clang to fcd by using `libclang`. While it worked for the task of parsing headers, it had a number of downsides:

* `Libclang` statically links LLVM too, so fcd's address space has two copies of LLVM living side-by-side. This is not a huge problem since `libclang` doesn't leak any LLVM object out, so there's no chance of mixup between the two, but it still feels clumsy.
* `Libclang` only exposes a small subset of the possible attributes that a function can receive. While most attributes have a larger impact on compilation, some of them provide very useful insight for decompilation as well. For instance, a call to a `noreturn` function (libclang doesn't expose the `noreturn` attribute) terminates a basic block just like a return instruction, but if a decompiler doesn't know that, it will think that the function continues beyond the call, which will (at best) make a huge mess.
* As `libclang` doesn't leak any of its internal LLVM details, it can't be used to take a `clang::FunctionDecl` (which is what we essentially get out of `libclang`) and extract a `llvm::FunctionType` (which is what fcd needs) out of it.

Because of that, fcd links against the Clang static libraries. They (essentially) solve these problems at the cost of an inscrutable memory ownership model. Right now, the implementation lives in [fcd/header_decls.cpp][2].

# Passing headers to fcd

To support this new feature, fcd gains two new command-line options:

* `-I` to add an include directory (can be specified multiple times);
* `--header` to `#include` a header name.

While nothing prevents you from writing your own header file, right now, fcd will only use header declarations for function stubs. Allowing users to somehow pass their knowledge of the program that they're decompiling to fcd is **definitely** on the radar, though.

Here's a small program that will write "Hello World!" to a path passed as the first parameter:

{% highlight c %}
#include <stdio.h>

int main(int argc, const char** argv)
{
	FILE* f = fopen(argv[1], "w");
	fputs("Hello World!\n", f);
	fclose(f);
}
{% endhighlight %}

Without header information, fcd does a rather poor job at figuring out what's going on:

{% highlight c %}
// $ fcd hello
void main(uint64_t rip, uint64_t rsi)
{
	fopen(4195775);
	fwrite(4195801);
	fclose(4195809);
	return;
}
{% endhighlight %}

However, with header information, we get something that actually makes sense:

{% highlight c %}
// $ fcd --header stdio.h hello
void main(uint64_t rip, uint64_t rsi)
{
	struct _IO_FILE* anon1 = fopen(*(uint8_t**)(rsi + 8), (uint8_t*)0x400674);
	fwrite((uint8_t*)0x400676, 13, 1, anon1);
	fclose(anon1);
	return;
}
{% endhighlight %}

Interestingly, we can see that Clang promoted the call to `fputs` into a call to `fwrite`.

Of course, this example highlights that fcd doesn't do a great job with string literals (and that it doesn't know about `main`'s signature). However, getting better type information is an obvious first step in in determining what should be displayed as a string literal.

## Passing foreign headers to fcd

Anyone who's been watching fcd is probably aware that my main development environment is macOS. However, while macOS standard library headers are generally source-compatible with Linux standard library headers, they are certainly not equivalent. For instance, on macOS, `fopen` boils down to `_fopen`, and as we've said before, on Linux, `putc` becomes `_IO_putc`. This means that you can't easily "just include" your own machine's headers if you're decompiling a program that targets a different platform.

Fortunately, getting Linux headers on macOS (or any other platform) is quite easy. For instance, since I know that the program is an x86_64 Linux program using glibc, it's quite easy to just [head to a package repository][3] and download the package for `libc-devel`. After decompressing the .deb and then the data.tar.gz archive, fcd can be pointed to the right location with the `-I` parameter. For instance, I would use this invocation of fcd on macOS:

    $ fcd \
          -I /tmp/libc6-dev_2.24-2_amd64/data/usr/include \
          -I /tmp/libc6-dev_2.24-2_amd64/data/usr/include/x86_64-linux-gnu \
          --header stdio.h \
          hello

This command has the same result as running fcd on a machine where these headers are actually installed.

In a future where fcd supports Mach-O programs, Apple provides downloads to its [Libc source][4] (this links points to the macOS 10.11.5 release), which could probably fulfill a similar role on non-Apple platforms.

The Windows situation is a bit more complicated, as the [Windows SDK installer][5] is a .exe program that is more involved than a self-extracting archive. Having not looked at the SDK license, it is possible that this use violates the EULA, too. That bridge will be crossed in time.

# Looking forward

This new feature unblocks a lot of type information that can be used for inference, and this will probably be my next focus. It'll also be interesting to add C++ support here, as it introduced as slight regression (the hard-coded list contained mangled C++ names).

Additionally, using headers to specify information about functions found in the program itself is a great point of interest.

Finally, at the moment, fcd has its own code to take a function prototype and figure out which locations will be used to pass parameter. It is known that LLVM can do that translation too, and it can certainly do it better. However, the specifics are nebulous. This will hopefully be investigated at some point in the future.

  [1]: {% post_url 2016-02-16-lifting-x86-code %}
  [2]: https://github.com/zneak/fcd/blob/089dba9f01443f9ebac5e8ac2b93a518d5408a08/fcd/header_decls.cpp
  [3]: https://packages.debian.org/sid/libc6-dev
  [4]: https://opensource.apple.com/release/os-x-10115/
  [5]: https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk