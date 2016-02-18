---
layout: post
title:  "The Region Problem"
date:   2016-02-17 17:17:48 -0500
---

<style type="text/css">
svg path {
	fill: none;
	stroke-width: 5;
	stroke-linecap: butt;
	stroke-linejoin: miter;
	stroke-miterlimit: 4;
}

svg text {
	font-size: 42.78px;
	font-family: Helvetica, Arial, sans-serif;
	font-weight: bold;
	fill: #000;
}

svg .fill-black { fill: #000; }
svg .fill-white { fill: #FFF; }
svg .stroke-gray { stroke: #85888D; }
svg .stroke-black{ stroke: #000000; }
svg.blue .stroke-blue { stroke: #51A7F9; }

svg.endless .hide-for-endless-loop path {
	fill: none;
	stroke: none;
}
</style>

Decompilers vary greatly in their ability to produce structured code. The main
reason is that at the machine level, code isn't neatly organized in if-else
statements and for loops: it's a graph of [basic blocks][2] connected by `goto`
statements. In general, optimizations will tear apart any remaining structure in
a compiled program.

<figure>
{% include svg/2016-02-17-structuring-1.svg %}
<figcaption>An example control flow graph.</figcaption>
</figure>

Control flow structure recovery is still an active research topic, with academic
papers and experiments coming out every now and then. However, as I was
designing fcd, one in particular caught my attention: [No More Gotos][1], by
German-affiliated researchers K. Yakdan, S. Eschweiler, E. Gerhards-Padilla and
M. Smith.

Up to then, the accepted technique for re-structuring control flow graphs was to
find isomorphisms to try and match little bits of the function against known
patterns, and use `goto` statements when that doesn't work. However, the *No
More Gotos* paper introduces a new technique called *pattern-independent control
flow structuring*, which, exactly as its name implies, structures a control flow
graph independently of any predefined patterns.

Before we go any further, I would like to tip off my hat to the authors. I'm not
an academic and I haven't read that many papers, but truth to be told, I
couldn't make anything out of the majority of papers that I did read. (So much
for reproducible science!) However, the No More Gotos paper is a well-written
piece that I was able to understand *and* implement. My appreciation might not
get them a grant, but if they ever read this, I hope that it makes them feel a
little warmer on the inside.

Fcd implements the technique in a couple of more or less distinct steps:

1. Ensure that each loop only has one entry and one exit;
2. Find regions in the control flow graph;
3. Compute the reaching condition of each block;
4. Simplify and merge control flow statements.

As it turns out, there is a lot to explain about that, so this post will cover
only one topic. Since #2 helps understand why #1 is important, we'll do things
out of order and go with finding regions in the CFG.

## Finding regions in the control flow graph

In compiler theory, a region is defined by a entry edge and an exit edge, where
the entry edge dominates the exit edge; the exit edge post-dominates the entry
edge; and any cycle that includes one also includes the other.

Less formally, control enters through only one edge and leaves through only one
edge.

One problem with this definition is that it fits poorly with LLVM's intermediate
representation. In the LLVM IR, graph nodes are first-class citizens but graph
edges are not. Fortunately, regions can very easily be adapted to a definition
that uses nodes instead of edges: we simply say that control enters through a
single node and exits through a single node.

This has the added convenience that we no longer need a single edge going in
or out of a region, we merely need all the out-going edges to point to the same
block.

<figure>
{% include svg/2016-02-17-structuring-1.svg svgclass="blue" %}
<figcaption>Our example control flow graph, with regions highlighted.</figcaption>
</figure>

Because regions are defined in terms of nodes instead of edges, the exit node of
the region is the node that succeeds the region. It is therefore not considered
part of the region (kind of like how a container's `end()` actually lies one
past the end). For instance, *H* is *EFG*'s exit node, but it is not highlighted
with *EFG*.

Because I didn't know what I was doing, I eagerly discounted LLVM's region
detection algorithm and ended up writing my own. I now view this as a mistake,
and I would eventually like to rework that part of fcd (though that is unlikely
to happen any time soon, unless fcd's region handling code proves to be a source
of problems). There isn't much use in expanding on how fcd currently does it, as
the solution, while not a bottleneck right now, is known to be inefficient
compared to the state-of-the-art approaches.

## The Post-Dominator Tree

LLVM's algorithms are not perfect either. The major weakness that I've
identified is that it relies on a post-dominator tree without verifying that
it's complete. As a matter of fact, the post-dominator tree building algorithm
produces an incomplete result for functions that have nodes that can't reach an
exit: in other words, if the function has an unbreakable endless loop.

<figure>
{% include svg/2016-02-17-structuring-1.svg svgclass="endless" %}
<figcaption>
	By removing the <em>D</em>→<em>E</em> edge, it's impossible to leave from
	<em>BD</em>. This causes all sorts of problems.
</figcaption>
</figure>

This happens because region detection walks down the post-dominator tree. To see
why this is a problem, we need to see how LLVM builds it. It scans the function
for returning nodes as starting points, and then uses the `predecessors`
function to traverse edges backwards: it would start with *H*, find *F* and *G*,
and then find *E*, then *C*, etc. However, there's no backwards edge "going
into" an endless loop: it can only be accessed through a forward edge (in this
case, the *A*→*B* edge). This means that *B* and *D* are never visited and not
made part of the post-dominator tree.

Any branch missing from the post-dominator tree translates to missed or
unstructurable regions, so this is a very serious problem. I couldn't think
right about it and ended up [asking for help on Stack Overflow][3]. The question
got more attention than I thought it would given how specific it was, and I
implemented a workaround in fcd based on Chris Dodd's answer. In my own words:

> I settled on this: (1) ask LLVM to make its post-dom tree; (2) find every back
> edge in the function; (3) check if every back edge destination has a tree
> node. If so, use LLVM's post-dominator tree. Otherwise, take the tree's root
> and add every back edge destination that didn't have a tree node as a root,
> and calculate a new post-dominator tree. It appears to work.

I haven't extensively studied fcd's output when it needs to patch up the
post-dominator tree like that, but I would tend to think that it's not the
end-all solution. However, "not amazing output" is still better than no output
at all.

## The Result

Anyway, the reason that we try to find regions in the graph is that they map
well to higher-level control flow structures. For instance, the *BD* region is a
loop that includes *B* and *D*, and *D* tests a condition to see if the loop
should continue or break, much like this:

{% highlight c %}
while (true)
{
	B();
	D();
	if (!D_cond)
	{
		break;
	}
}
{% endhighlight %}

In turn, this block is easy to embed into the *ABCD* structure, which would look
like:

{% highlight c %}
A();
if (A_cond)
{
	while (true)
	{
		B();
		D();
		if (!D_cond)
		{
			break;
		}
	}
}
else
{
	C();
}
{% endhighlight %}

The resulting code has a few possible readability tweaks, but this is starting
to reach into *Simplify and merge control flow statements* territory, so we'll
leave it there for today.

Pattern-independent control flow structuring distinguishes between regions that
contain conditions and regions that contain loops. Loops can only be
structurized if the region is entirely about them; that is, the entry of the
region is the entry of the loop and the exit of the region is the exit of the
loop. This is why loops must have a single entry and a single exit; otherwise,
they wouldn't map cleanly to regions. How fcd ensures this will be a topic for a
future blog post.

  [1]: http://www.internetsociety.org/doc/no-more-gotos-decompilation-using-pattern-independent-control-flow-structuring-and-semantics
  [2]: https://en.wikipedia.org/wiki/Basic_block
  [3]: http://stackoverflow.com/q/35399281/251153