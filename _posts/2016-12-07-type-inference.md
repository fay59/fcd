---
layout: post
title: "Kicking off the holidays with type recovery"
---

<style>
.small {
	font-size: 9pt;
	opacity: 0.6;
}
</style>

Last time, I [wrote][1] that fcd frequently hung or crashed because of problems in three broad categories:

* loop structurization;
* complex reaching conditions;
* stack frame recovery.

Since then, the update to structurization has landed in the master branch, which solved every known occurrence of crashes in the first two categories (though, granted, my test set is still rather limited). It's not mission accomplished yet, as there are still areas where structurization needs to improve. For instance, [nested loops are collapsed into one big fat loop][2]. I'm also aware that the No More Gotos authors have published a follow-up paper, *[Helping Johnny to Analyze Malware][3]*, that I have only quickly glanced over.

Still, stability was a clear winner in this merge. As a consequence of this improvement, stack frame recovery became fcd's number one cause of failure.

The recovery of the stack frame is a special case of the type recovery problem. Recovering the variables of a stack frame is a simpler version of the problem of recovering the fields of a structure. Another special case is the recovery of global variables. Fcd doesn't try it at the moment, but a good type recovery algorithm could solve that.

Since an algorithm for stack frame recovery was implemented, the end goal has been that it should be replaced with a more general pass at some point in the future. We're (hopefully) approaching this time, so I'd like to share some observations about how fcd does it.

I initially wanted to make one post for the whole feature, but there is an awful lot of things to cover around type recovery (and a lot of problems to solve), so let's start with an overview of what's to do.

As an aside: this problem is frequently called "type inference", but I strongly prefer "type recovery". I find that it describes better what we hope to achieve. With modern languages, "inference" has this calmly-glowing aura around it that the compiler/interpreter *just knows* what you're talking about when you declare all of these variables without explicitly typing any. Recovery feels more like "use as much duct-tape and WD-40 as you need to make something useful out of this mess".

There's also an implementation detail of fcd that deserves recognition on this topic: because of the SSA form, structure-typed LLVM values rarely exist for a long time. The framework will almost always trivially break them up into individual variables before it gets to pseudo-C code generation. What really matters is the type of memory (and thus of pointers), because LLVM can't systematically break up structures that live in memory, as much as we would benefit if it could. For this reason, this post focuses on the problems of recovering the `Foo` in `Foo*`.

# The type problem

Type recovery is easy in a world where things have one unambiguous type. For instance, a structure with four fields can easily be recognized by the analysis of a function that accepts a pointer to it and manipulates every field individually. Unfortunately, the story for most languages is much more complicated than that.

In most native languages, the program could choose to cast a pointer to a different and arbitrary type. For instance, a `uint64_t*` can be casted to a `double*`. This could cause undefined behavior in some high-level languages like C++, but machine code generally doesn't have undefined behavior: it has been frozen and the same sequence of operations is expected to have the same result every time, disregarding randomness-as-a-feature modifiers like ASLR.

Most interesting native languages also have some concept of a union, where a variable has one type out of many predefined possibilities. In C, this is just a `union`-tagged record. Other languages, like Swift, have discriminated unions, which are basically unions made safe by storing information about which member is being represented.

Subclasses can also be considered a form of unions. In object-oriented languages, it is not excluded that a pointer to an object is, in fact, a pointer to a larger object. For instance, with a base class `Base` that has a subclass `Derived`, if a function accepts a pointer to a `Base`, you could pass in a pointer to a `Derived`. The function itself is binary-compatible with either type, as they respect the prefix object layout of `Base`.

Things get a little weird when you put multiple inheritance in the picture. When this happens, suddenly, you can't just take `Derived*` bits and expect them to represent valid `Base*` bits. The language needs to do pointer adjustment. In this simple example:

{% highlight c++ %}
struct Base1 { int foo; };
struct Base2 { int bar; };
struct Derived : public Base1, Base2 { int frob; };
{% endhighlight %}

C++ will allow you to pass a `Derived*` to a function that accepts a `Base1*` or a `Base2*`, but the conversion is not a noop at the machine level. The two base classes, obviously, can't occupy the same memory location. This is one possible flat representation of the `Derived` structure:

{% highlight c++ %}
struct Derived { Base1 base1; Base2 base2; int frob; };
{% endhighlight %}

When you pass the `Derived*` to a function accepting a `Base2*`, the compiler will adjust the pointer and pass the equivalent of `&derived->base2`.

The place where things get *really* weird, however, is when you have a function that casts the `Base2*` to a `Derived*`. To do this, the compiler's only option is to adjust the pointer by a negative amount. This manipulation is generally perceived as scary, and my observation is that it is poorly understood by disassemblers and decompilers.

(This doesn't account for virtual inheritance. To be honest, I've never even looked at how this one is implemented in any ABI.)

Even when you don't have to adjust pointers, a mere pointer cast can easily throw a wrench in type recovery. Here is another simple C++ hierarchy:

{% highlight c++ %}
struct Base { int type; };
struct Derived1 : public Base { double bar; };
struct Derived2 : public Base { uint64_t bar; };
{% endhighlight %}

If you have a function that accepts a `Base` and casts it to a `Derived1` or `Derived2` depending on whether `Base::type` is 0 or 1, it would be an error for a type recovery engine to pretend that this function operates on a single type. While this is often considered poor object-oriented design (*something something* virtual methods), it is encouraged in languages that have discriminated unions, or in frameworks where developers are savvy of other programming paradigms.

Another problem is that as compilers and languages become smarter, native programs carry less and less hints of their original data types. For instance, when copying Swift structures, the compiler will happily load the whole thing in a vector register and copy it to another memory location, without any respect for field boundaries. This obviously doesn't mean that the type was a vector type to begin with; it just happens to be the fastest way to get memory from one place to the other.

# The pointer problem

As the name implies, the high-level objective of type recovery is to recover types. However, you need to be able to identify pointers before you're able to try to find out what pointers reference. In fcd's stack frame recovery pass, this is easy: the only pointer that it recognizes is the stack frame pointer, passed as an argument to the function, and tagged with the `fcd.stackptr` metadata attribute. (After recovery, this parameter is removed from the function's signature.) Sadly, the general case is much more complicated.

* Some pointers are passed in as arguments to a function. This is a generalization of the case that fcd already handles. However, while fcd knows that the stack parameter is *always* a pointer, it can't make that assumption about every function parameter.
* Some pointer parameters are just *part-time pointers*. For instance, in the x86_64 System V ABI, a structure like `struct { int type; union { long i; void* p; } value; };` passed by value will be spread over argument registers, with `type` going in `rdi` and `value` going in `rsi`. This puts `rsi` in some tricky superposed state where it is both a pointer and an integer until observed. Of course, this also applies to return values: returning the same structure by value would put `type` in `rax` and `value` in `rdx`.
	* This also speaks of another distinct problem: exact argument type recovery is difficult/impossible when structures are broken up.
* Global variables are usually referenced by address in a compiled program. This also covers the case of magic memory locations like memory-mapped device registers.
* Some pointers are dynamically allocated and are obtained as the result of a function call, using `malloc` or another allocation routine.
* Some pointers are obtained as an "out" parameter to a function (like `allocateStuff(size, &stuff)`, where `stuff` is a pointer). Sometimes, the caller of `allocateStuff` won't even try to reference anything inside `stuff` after it gets a value (a case that the stack frame recovery pass handles very poorly at the moment).
* Some pointers are obtained by offsetting another pointer by a constant or variable amount of memory, as in `a[b]`: the pointer `a` offset by the integral value `b`, times `sizeof *a`.
* Some pointers are obtained by dereferencing other pointers.

Almost all of these cases have "what if"s and "but"s attached to them, making the challenge of identifying pointers at least as important as finding what they point to.

In the general case, it's not possible to start from a root value and walk down its branches to find every pointers used by a program like the stack frame recovery pass does. The only good way to identify pointers appears to be to find memory instructions in a program and identify their memory operands. Memory instructions here refer to `load` and `store`, of course, but also to `call` instructions, which may accept and return pointers. Since we are doing this in part to figure out the type of function parameters, if the program uses recursive functions, the result of this analysis may end up depending on itself.

Another problem is that to get good results, you almost certainly need to unify the type of different pointers: that is, you assume that two pointers point to the same type of memory. This lets you apply your findings to multiple values at once. The obvious issue is that, for any of the reasons mentioned in this section, compounded with any reason mentioned in the previous section, the assumption could be incorrect. Trying to provide a sound solution to this problem looks like a losing battle, but there will need to be some cutoff or heuristic that is "good enough".

# Going forward

I'm writing this because it helps me put my thoughts in order about what I'm going to have to do. I don't have anything worth showing at the moment, but I swear, it's getting there. <span class="small">Hopefully this doesn't become one of these posts that have no follow-up four years later.</span>

An issue with all of this is that type recovery is pretty involved and somewhat of an academic field, which puts me outside of my element as I do not pursue an academic career. In fact, I never even had a class on type theory or compiler principles. I feel that it puts me at a handicap when trying to figure out type inference papers.

I looked around and found two papers that felt like they were promising: the [TIE paper][4] ([open-source implementation in OCaml here][5]) and the [paywalled SmartDec paper][6] ([open-source implementation that hasn't been touched since the original commit here][7]).

A problem with the TIE paper is that I've never been taught the logical language and several concepts that they use in the paper to describe their inference technique; but from what I understand, it would do a poor job at recovering polymorphic types (where polymorphism is used in its object-oriented sense). The part that I think that I understand is the one about recovering the type of values instead of the type of pointed-to memory, which is less relevant in the LLVM world.

A problem with the SmartDec paper is that they parse RTTI, and failing that, they look at constructors and destructors. RTTI is complex to parse, easy to mess with, ABI-specific, and it only exists in C++ programs when it has not been turned off. Constructors and destructors are only useful if they exist (which is not a given, even in C++: they could be trivial or inlined), and if they can be identified. The approach is too specific for what fcd wants to be.

Confronted with a solution that I don't understand very well and a solution that I don't believe in, the best way forward might just be to make something up. But then again, given the nature of the task and my background, it might not. This is going to be exciting.

I still think that I have a decent idea to cover most cases of polymorphism using the dominator tree of a function to draw a line between types that it's okay to keep un-unified. I still need to do first things first, though, and git gud at pointer discovery. I'll publish an update with nice figures and a new Git branch when things get more concrete.

 [1]: {% post_url 2016-11-25-revisiting-regions %}
 [2]: https://github.com/zneak/fcd/issues/33
 [3]: https://net.cs.uni-bonn.de/fileadmin/ag/martini/Staff/yakdan/dream_oakland2016.pdf
 [4]: https://users.ece.cmu.edu/~dbrumley/pdf/Lee,%20Avgerinos,%20Brumley_2011_TIE%20Principled%20Reverse%20Engineering%20of%20Types%20in%20Binary%20Programs.pdf
 [5]: https://github.com/BinaryAnalysisPlatform/bap
 [6]: http://ieeexplore.ieee.org/xpl/freeabs_all.jsp?arnumber=6079860
 [7]: https://github.com/smartdec/smartdec
 