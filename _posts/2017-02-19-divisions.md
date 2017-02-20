---
layout: post
title: How do compilers optimize divisions?
---

{% include mathjax.html %}

A fun part of writing a decompiler is trying to figure out how a compiler got from point A to point B. Compilers are known to use every last trick in the book to make things just marginally faster. Sometimes, compilers are just a bit clever: for instance, Clang can codegen a switch statement with lots of disjoint cases as a binary search over the cases to get better average- and worst-case number of comparisons. Anybody reading the code can see how it made sense to do that. Sometimes, however, compilers get *really really* clever and figuring out what happened is not a straightforward process.

One example of a non-obvious optimization is what compilers do for divisions by a constant. Divisions are still hard, and compilers hate to emit a `div` or `idiv` if they know one side of the equation. The resulting code, however, is puzzling.

{% include godbolt.html source="unsigned udiv19(unsigned arg) {
	return arg / 19;
}" %}

Up to very recently, fcd wouldn't see the division in there and would produce output similar to the following:

{% highlight c %}

uint32_t udiv19(uint32_t arg0)
{
	uint64_t anon1 = (__zext uint64_t)arg0 * 2938661835 >> 32;
	return (uint32_t)(anon1 + ((__zext uint64_t)(arg0 - (uint32_t)anon1) >> 1) >> 4) & 0x0fffffff;
}

{% endhighlight %}

## What happened?!

This doesn't quite look like a division by 19. Of course, that's a problem for fcd, because we want to help people make sense of what they're looking at.

Generally speaking, you can't divide without dividing. What happened here is that Clang (and most other compilers up at Matt Godbolt's [Compiler Explorer][1]) simply resort to using the one and only type of division that computers are really good at: divisions by a power of two. There's no `div` instruction in sight, but we do have right shifts. In fact, we can rewrite this code as a questionably better-looking mathematical expression:

$$
\begin{align*}
	a \cdot \frac{1}{19} &\approx
		\frac{a \cdot \frac{2938661835}{2^{32}} +
	    \frac{a - a \cdot \frac{2938661835}{2^{32}}}{2^1}}{2^4} \\\
	a \cdot \frac{1}{19} &\approx
		\left(
			a \cdot 2938661835 \cdot 2^{-32} +
			\left( a - a \cdot 2938661835 \cdot 2^{-32} \right) \cdot 2^{-1}
		\right)
		\cdot 2^{-4} \\\
	a \cdot \frac{1}{19} &\approx
		a \cdot \frac{7233629131}{137438953472} \\\
\end{align*}
$$

(The `& 0x0fffffff` that fcd shows and that we ignored here is a leftover from the earlier phases of decompilation, where every 32-bit integer is represented as a 64-bit integer masked with `0xffffffff`. Most of these masks go away, but in this specific case, the mask was combined with the `>> 4` and the result isn't obvious enough to let fcd get rid of it outright.)

The result of 7233629131 / 137438953472 is 18.999999997649866. In other words, the compiler merely found a big factor (2938661835) with which you could relatively easily compose divisions by powers of two until you'd *almost* get a division by 19.

How close is close enough? Given that we divide an unsigned 32-bit number, this has to be accurate for integers up to 4294967295. 18.999999997649866 is not quite 19, and this is integer division, so the denominator needs to be `ceil`ed to be accurate. We get an error margin of `ceil(denom) - denom`, and we want to know when enough error has accumulated that we'll get a difference of 1. If that point happens further than 4294967295 / 19, then the approximation is valid for every integer in our division domain. We need to check for this:

$$
\begin{align*}
	\frac{1}{19 - 18.999999997649866} &\ge \frac{4294967295}{19} \\\
	425507595.8885449 &\ge 226050910.2631579
\end{align*}
$$

It holds, meaning that the approximation is accurate for any unsigned 32-bit integer that we can throw at it. Yay! This verification is important, because we wouldn't want to transform something that is not really a division into a division.

## Generalizing

Clang generates 5 or 6 different patterns to divide by (or get the remainder of division with) constant integers. Interestingly enough, there is little to no variety in how signed division works, but there are several distinguishable patterns with unsigned division.

For the pattern that was just discussed, as a lazy person, I just threw the formula in [Wolfram\|Alpha][2] and asked it to isolate the denominator in it:

$$
\begin{align*}
	\frac{a}{D} &\approx \frac{\frac{aC}{2^{X}} + \frac{a - \frac{aC}{2^{X}}}{2^Y}}{2^Z}
\end{align*}
$$

Where $$a$$ is the numerator (which is variable), $$D$$ is the denominator (which we want to find), $$C$$ is the large multiplier constant, and $$X$$, $$Y$$ and $$Z$$ are the different exponents of two that are used for right shifts. It came back with this:

$$
\begin{align*}
	D &\approx \frac{2^{X+Y+Z}}{C \cdot \left(2^Y-1\right)+2^Z}
\end{align*}
$$

This formula is easy enough to plug into fcd, and the verification code is equally easy to use.

I didn't find a lot of documentation about this optimization. [RE.SE][3] has two answers to this question; the most upvoted one uses an example to show how you could come up with these numbers and covers one case the hard way. [Compiler people][4] have better information on how to come up with these numbers, but this is somewhat beyond what I'm interested in for fcd's purposes.

As of this time, fcd gets signed division and remainder right, unsigned division right, and *some* of unsigned remainder. It turns out that the unsigned remainder operation does a few weird things that I'm not sure how to interpret, and unfortunately, my lazy options are more limited as Wolfram\|Alpha has trouble understanding modulos (or, more probably, I have trouble expressing what I want to do in its language). Still, I'm happy to report that `udiv19` now decompiles as `arg / 19`.

  [1]: https://godbolt.org/
  [2]: http://www.wolframalpha.com
  [3]: http://reverseengineering.stackexchange.com/questions/1397/how-can-i-reverse-optimized-integer-division-modulo-by-constant-operations
  [4]: https://blogs.msdn.microsoft.com/devdev/2005/12/12/integer-division-by-constants/
  