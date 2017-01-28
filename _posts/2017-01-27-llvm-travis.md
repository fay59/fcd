---
layout: post
title: LLVM 4.0, Travis CI, type reconstruction–oh my!
---

Well, it's been [two months since I said][1] that I'd have something to show for type recovery after one month. I'm afraid that I'm still not quite there, but I do have some things to discuss. And fortunately, things haven't been at a complete standstill either: LLVM is releasing a stable 4.0 in a few weeks, and fcd is getting continuous integration.

# LLVM 4.0

As expected around this time of the year, LLVM has a new stable release coming up. I like to pick up the release candidates because fcd does unusual things with LLVM IR (centered around the fact that it goes from machine code to source instead of the other way around), and I want to make sure that I won't be locked
on the old version for a few months because there's a bug in the new version that only impacts fcd and that prevents me from picking it up. (Testing 3.9 [did find such a regression][2].)

With 4.0, LLVM is inching ever closer to removing the element type from pointer types, and have a single `*` pointer type. Between 3.9 and 4.0, `PointerType` stopped being a `SequentialType`. This is probably most impactful when you generate `getelementptr` instructions by hand, and thankfully, fcd doesn't need to do much code generation by hand.

While there wasn't too much trouble with the new release around this, I expect that it will become a problem in the future, especially for type recovery. External function calls provide very valuable type information, but fcd largely relies on function signatures having typed pointers to benefit from them. While `PointerType` no longer inherits from `SequentialType`, it gained a `getElementType()` method that does the same thing the one that  `SequentialType` gave it. I expect this method to disappear in a not-so-distant future. This means that fcd will need to figure something out to carry the information over from C headers to LLVM function declarations.

On its end, Clang brought microscopic improvements to memory management in the tiny API surface that fcd uses. The single noticed improvement is that `ClangInvocation` now uses `unique_ptr`/`shared_ptr` instead of an `IntrusiveRefCntPtr` in front-facing APIs. In all fairness, fcd's use of Clang is superficial enough that I'm probably just missing on all the goodness.

As for improvements, what we're seeing is about on par with what I expected out of an already very mature compiler framework: not much of a change for the purposes of decompiling. The output is usually exactly the same size; frequently a tiny bit smaller; sometimes a tiny bit bigger. There could be some cool new things waiting to be used; I'll have to look into that.

# Continuous Integration with Travis

I've recently flipped the switch to build fcd with Travis. I finally bit the bait when prompted about it on [Trass3r's pull request on the CMake files][3].

I had never used Travis before, so this was quite the new experience. Overall, I guess that it's hard to beat free, but I can't say that I'm super impressed with the build environment in the context of native programs. My feeling is that Travis was built with Web applications in mind.

Travis gives us either Ubuntu 12.04 (Precise) or 14.04 (Trusty), which are respectively 5 years old and 3 years old distributions. Capstone has packages for neither. The installation of LLVM 3.9 (soon-to-be 4) is non-obvious as well. The standard libraries are outdated and newer versions need to be grabbed from added repositories. The macOS build works, but the environment frequently take over 45 minutes to prop up.

And of course, testing scripts is made more complex by the fact that the only real way to test continuous integration is to commit changes. In my short time using Travis, I haven't found a reliable way to reproduce their environment locally.

But enough negativity. Beyond answering the simple "does this build" question, through its shell script capabilities, Travis also lets us run automated tests and put results somewhere. I created the [fcd-tests][4] repository, where I store my usual test suite of little programs, and I have Travis clone it, decompile every one of them, save the output, and push it back to Github. This afford some relative peace of mind, and hopefully will help figure it out faster when something breaks. Yay!

Still, this isn't a perfect solution. The main reason that I've held off on continuous integration for so long is fcd's nebulous criteria for success. Of course, crashing is a failure, but what about mis-decompilations? There is currently nothing in place that will tell you if fcd's output is blatantly wrong. At best, checking in results to a Git repository means that once an issue is discovered, it *could* be doable to go back in time and find the first revision that exhibits the problem.

Comparing two output revisions is possible, but fcd has non-deterministic output. As [outlined in some version of fcd's wishlist file][5], this is most likely caused by `unoredered_map`s and `unordered_set`s using ASLR'd pointers as keys. I find that the output is fairly stable within basic blocks and on control flow graphs that don't have cycles, but functions with loops tend to look very different from one run to the other.

Another obvious consequence of this move is that it allows anyone to look at fcd's output. This is equal parts great and scary. It possibly raises awareness about the project and lets people know what they're getting into. It makes it simpler to identify low-hanging fruits that could be picked up by newer contributors. However, it exposes all the things that I'm self-conscious of and want to fix at some point but haven't fixed yet and that gives me shipping anxiety.

Looking back, using IOCCC programs as test cases for a decompiler is a fun idea, but the reality is that they commonly use very brutal gotos and other [weird constructs][6]. That commonly results in garbage control flow graphs. The problem with these is that they're not representative of the real world, and fcd doesn't always do a great job on them, so it probably looks worse than it would look on programs written by humans (as opposed to programs written by [monsters][7]).

One thing that I might/should start looking into is integrating old CTF binaries in this testing pipeline. CTF hosts, let me know if I can take your stuff!

# Type Reconstruction

Progress on type reconstruction has been going at a baby steps pace, but as a wise man once said, baby steps are just as good as adult steps if the fact that there are no venture capitalists to pressure you means that you can make enough of them.

The 10,000-meters high view (that's over 30,000ft!) is that fcd uses some constraint solving over the whole program to figure out values that are pointers, and it organizes them in hierarchical tree structures. For instance, it determines that some value A is a pointer, and that this value A + 16 is also a pointer, and makes this a logical descendant of A. A second step (that does not do constraint solving at the moment) is run over the output of this first step, and wrangles this tree-like structure in somewhat flat records, also across the whole program.

As somewhat of a novelty, the dominator tree will be used as a heuristic to distinguish subtypes, but as this post is getting quite long, I'm keeping that one for later. Sorry for everyone who hoped that I'd have a true update on type reconstruction! I don't really.

But I swear, I'm working on it.

  [1]: {% post_url 2016-12-07-type-inference %}
  [2]: http://lists.llvm.org/pipermail/llvm-dev/2016-August/104018.html
  [3]: https://github.com/zneak/fcd/pull/17
  [4]: https://github.com/zneak/fcd-tests
  [5]: https://github.com/zneak/fcd/blob/c0c14509e458e0e60d19c44a08fe21fcafb790c2/FUTURE.md#stabilize-output-across-runs
  [6]: https://en.wikipedia.org/wiki/Duff's_device
  [7]: http://www.ioccc.org/winners.html
  [8]: https://github.com/GavinHigham/ceffectpp
