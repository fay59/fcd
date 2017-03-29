---
layout: post
title: "Helping Johnny to Analyze Malware: Part 1"
---

When I presented at CSAW, Assistant Professor [Brendan Dolan-Gavitt][1] told me that the authors of the [*No More Gotos* paper][2] released a second paper that describes enhancements that they implemented in their Dream decompiler (now called Dream++). The paper, [Helping Johnny to Analyze Malware][3], explains how some improvements were implemented, and pits the Hex-Rays decompiler against Dream++ in a comparative study.

It took me a while to get to it (basically, until I finally decided to push off type reconstruction again–sorry 😞), and a handful of ideas aren't directly applicable to fcd. For instance, the code query and transformation tool that they describe seems to be a large amount of work for relatively little benefit considering that fcd already allows users to load in LLVM passes to execute. Of course, their system allows some simplifications that fcd is not superbly good at currently, but fcd still has more fundamental issues than "man, I wish that this `result = a > b ? a : b` statement turned into `result = max(a, b)`".

Two things stood out as very interesting, however. First, they introduce more loop transforms that help make loops better; second, they discuss transforms related to variable congruence. In addition, the part about making loops better inspired me to fix some long-standing problems with loop restructuration in fcd. Together, these improvements help make fcd's output actually look great in many cases.

Since I tend to write long posts, this will only cover variable congruence. I'll do loops–again–some other time.

## The Running Example

With [Jeff Crowell's permission][4], I pulled his Boston Key Party 2017's `hiddensc` challenge into fcd's test repository. Thanks, Jeff! It contains a short but interestingly demonstrative function that probably looked like this:

{% highlight c %}
unsigned long rand64()
{
	unsigned long result = 0;
	for (int i = 0; i < 64; ++i)
	{
		result <<= 1;
		result |= rand() & 1;
	}
	return result;
}
{% endhighlight %}

# The Initial State

Before I got into any of this, fcd often did a poor job with loops and variables. Here's the output as of March 18<sup>th</sup>:

{% highlight c %}
uint64_t rand64(uint64_t arg0)
{
	uint64_t phi3;
	uint32_t phi4;
	uint64_t phi_in1 = 0;
	uint32_t phi_in2 = 0;
	do
	{
		phi3 = phi_in1;
		phi4 = phi_in2;
		if (phi4 < 64)
		{
			uint32_t anon5 = rand();
			phi_in1 = (__zext uint64_t)(anon5 & 1) | phi3 << 1;
			phi_in2 = phi4 + 1;
		}
	}
	while (phi4 < 64);
	return phi3;
}
{% endhighlight %}

Don't like it much? Can't blame you. The output is at least twice as long, it indents deeper, and it went from using two variables to using 5.

There are some obvious improvements that can be made. First, we can get the number of variables down a bit. We can see that `phi3` takes its value from `phi_in1`, and looking at the code, it's clear that we don't really need two variables for this. How do you formalize it, though? Thankfully, Khaled Yakdan *et al.* have a solution for us.

## Congruence analysis of variable

The *Johnny* paper, as I'll call it from now on, describes a technique called *congruence analysis* to identify variables that really want to represent the same value. The technique is perfectly applicable to variables like the synthesized Φ variables that fcd creates, and it produces satisfying results. In a few lines, the rules go as follow:

* You can only merge variables that have the exact same type (for instance, *not* `int` and `short`).
* You can only merge variables that are assigned to one another.
* You can only merge variables whose definitions do not *interfere*.

The first two points are self-explanatory, but the third one could benefit from additional explanation. In this context, two variable definitions *interfere* when both variables are read sequentially with different values. For instance, in this very simple example:

{% highlight c %}
a = 4;
b = 5;
foo(a);
foo(b);
a = b;
{% endhighlight %}

Even though `b = a` in the end, `a` and `b` are read with different values at `foo(a)` and `foo(b)`, so the variable aren't congruent and we can't simplify this example to use just one variable.

{% highlight c %}
a = 4;
b = 5;
foo(b);
a = b;
{% endhighlight %}

Assuming that `foo(b)` doesn't modify either `a` or `b` through some freak global pointer or any other design faux pas (to be clear, this is just an example and fcd wouldn't dare to make assumptions about aliasing), then now, it's safe to have a single variable for every manipulation. You would merely remove the assignments to `b`, and use `a` everywhere it's used:

{% highlight c %}
a = 4;
a = 5;
foo(a);
{% endhighlight %}

To make these inferences, the *Johnny* paper explains that you can use the *live range* of the variables in question. The live ranges of a variable are the disjoint ranges of instructions starting from definitions to the last use of the variable before its next definition.

{% highlight c %}
a = 4;  // definition one of a. a is live
foo(b); // a is live
foo(a); // last use of a's definition one. a is live
foo(c); // a is *dead*
a = 5;  // new definition of a. a is live (again)
{% endhighlight %}

*Johnny* uses this property to determine if two variables are interference-free. In fact, the property of being interference-free is defined to be whether, with variables `a` and `b` again, `a` is assigned a value (other than `b`) in an instruction that is part of `b`'s live range, or vice-versa. If `a` is free of interference with `b`, and `b` is free of interference is `a`, then the two variables are said to be congruent, and should be merged.

This is currently implemented in [`pass_congruence.cpp`][5]. It doesn't solve the unnecessarily complex loop structure of the running example, but it does make things better:

{% highlight c %}
uint64_t rand64(uint64_t arg0)
{
	uint64_t phi1 = 0;
	uint32_t phi2 = 0;
	do
	{
		if (phi2 < 64)
		{
			uint32_t anon5 = rand();
			phi1 = (__zext uint64_t)(anon5 & 1) | phi1 << 1;
			phi2 = phi2 + 1;
		}
	}
	while (phi2 < 64);
	return phi1;
}
{% endhighlight %}

`phi_in3` and `phi_in4` are gone, which is great. `anon5` is still around because fcd hates to (re)move statements that have observable side-effects, though this has also been alleviated: expressions with side-effects can be moved up until to the next expression with side-effects, and in this case this allows us to remove the `anon5` variable and put `rand()` directly in the `phi1` assignment.

## The Future: more loop simplifications

The latest and greatest version of fcd also performs some loop simplifications. Currently, the output for the function has been reduced to a single, fairly nice loop:

{% highlight c %}
uint64_t rand64(uint64_t arg0)
{
	uint64_t phi1 = 0;
	uint32_t phi2 = 0;
	while (phi2 < 64)
	{
		phi1 = (__zext uint64_t)(rand() & 1) | phi1 << 1;
		phi2 = phi2 + 1;
	}
	return phi1;
}
{% endhighlight %}

This will be the topic of another post in due time, when some more of the suggestions in *Johnny* have been implemented.

  [1]: https://twitter.com/moyix
  [2]: https://www.internetsociety.org/sites/default/files/11_4_2.pdf
  [3]: https://net.cs.uni-bonn.de/fileadmin/ag/martini/Staff/yakdan/dream_oakland2016.pdf
  [4]: https://twitter.com/jeffreycrowell/status/835986452496297984
  [5]: https://github.com/zneak/fcd/blob/d41571c19f1fa610f348d8c60646215c7ccebc8a/fcd/ast/pass_congruence.cpp
  [6]: https://github.com/zneak/fcd-tests/blob/454827c02fc7ad6082989926dee3fea05a25abf7/output/bkp2017-hiddensc.c#L130