---
layout: post
title: "Revisiting Structurization"
---

<style type="text/css">
svg .cfg-node{
	fill: #ffffff;
	stroke: #85888D;
	stroke-width: 5;
	stroke-linecap: butt;
	stroke-linejoin: miter;
	stroke-miterlimit: 4;
}

svg .stroke-black{
	fill: none;
	stroke: #000000;
	stroke-width: 5;
	stroke-linecap: butt;
	stroke-linejoin: miter;
	stroke-miterlimit: 4;
}

svg .translucid {
	opacity: 0.25;
}

svg text {
	font-size: 42.78px;
	font-family: Helvetica, Arial, sans-serif;
	font-weight: bold;
	fill: #000000;
}

.wide svg {
	width: 100%;
}
</style>

From my personal set of test programs (which are mostly [IOCCC][4] entries), I can tell three main problems because of which fcd will fail to decompile some program:

* loop structurization breaks;
* complex reaching conditions grind fcd to a halt;
* stack frame recovery crashes.

As interest into fcd drips in, it's becoming harder to justify that it doesn't work all that often. Now that fcd has caught some attention with fun gimmicks that no one else has, it might be time to work on reliability.

The third problem is a type inference problem. Type inference has proved to be a tough nut to crack, so I decided to focus on the other two for now. They both live in the IR-to-AST layer, making it a prime target for enhancements.

# The Loop Problem, again

The pattern-independent control flow structuring technique, on which fcd is based, needs loops to have precisely one entry and one exit. Ensuring this property, it turns out, is complex. Back when I had the motivation to [do fancy SVG figures for these posts][2], I made it look easy enough:

> Once you have your entries, your loop members and your exits, you must ensure that there is a single entry node and a single exit node. If there are more than that, the pass creates a "funnel node" (my term) that collects every entering (or exiting, since the same algorithm is used for both cases) edge, creates a Φ node with a different value for every incoming edge, and directs execution to different blocks depending on its value.

One major problem with this approach at the IR level is that it gravely mangles the dominator tree. Suppose that you have nodes A and B inside a loop, which respectively go out to nodes C and D outside of it (a case of multiple exits). Also assuming that C and D have no other predecessors, it is obvious that A dominates C, and B dominates D: the only way to get to node C is by passing through node A, and the only way to get to node D is by passing through node B.

<figure class="wide">
{% include svg/2016-11-25-revisiting-regions-1.svg %}
</figure>

Unfortunately, when you stick a funnel node in this control flow graph, you have to direct both A and B to exit to it, and both C and D to succeed it: the domination relationships are broken. This means that without further adjustments, node C cannot reference a value created in block A, because LLVM does not realize that this value is, in fact, guaranteed to exist if we got to node C.

<figure class="wide">
{% include svg/2016-11-25-revisiting-regions-2.svg %}
<figcaption>Without looking at what's going on in the Φ block, you cannot know that A only goes to C and B only goes to D.</figcaption>
</figure>

(And these were the two figures for today. Thank you for watching.)

In the best-case scenario, this works but you now need a ton of new Φ instructions. As every Φ node causes *two* variables to be emitted, the proliferation of Φ instructions should be something that we want to avoid. And, of course, in the worst-case scenario, it doesn't work. Sadly, it didn't work in a lot of cases; dominating-no-more values would be missed, or back-edge detection would ironically spin into an endless loop.

## The Loop Solution

I determined that the simplest solution to these issues would be to ditch LLVM IR entirely at the point where we have to structurize loops. In itself, this is not a huge change: loop structurization was the second-to-last pass to run before creating the AST, with the last pass being a cleanup pass for loop structurization.

What happens now is that fcd creates a new "AST graph" based on the IR basic block graph. The AST graph initially has one node per IR basic block, and contains an AST representation of that basic block. Then, before structurizing it, we ensure that every loop has a single entry and a single exit. This is done by performing a depth-first search on each strongly-connected component of the control flow graph, starting at an arbitrary entry edge. The depth-first search detects back-edges and collects them. The final step is just to take each edge and direct them to a funnel block.

Since this graph deals with AST constructs, which are only loosely safe compared to LLVM IR, there is no need to create any new LLVM Φ node. Funnel blocks do not match any IR block, and a single AST variable is introduced to represent what would have been a Φ node in the IR.

The case where loops have no exit is also important to consider. Loops without exits are a problem because the post-dominator tree algorithm starts its work by looking at a function's exits and walk up to the entry; if a loop never exits, then the algorithm will never reach it. Previously, this problem was solved using the shotgun approach of adding fake roots to the post-dominator tree in any place that looked like it could be necessary. Now that fcd has a flexible graph that can be modified without impacting the LLVM representation, fcd adds a fake edge going to a fake exit to the loop header. This edge's reaching condition is `false` and as such never appears in decompiled output. This largely harmless change is all that the post-dominator tree builing algorithm needs to be happy again.

# The Region Problem, again

I took the opportunity to revisit my quick choice of doing region detection myself, and try to use the LLVM infrastructure for it. I [wrote][1] before:

> Because I didn’t know what I was doing, I eagerly discounted LLVM’s region detection algorithm and ended up writing my own. I now view this as a mistake, and I would eventually like to rework that part of fcd.

Although not algorithmically or stylistically great, fcd's region detection code did get the job done. My hope was that I could make the code both algorithmically better and more readable by using LLVM's region tools this time around.

Unfortunately, even though my reasons to roll out my own region detection code at the time were flawed, it turns out that LLVM's region code is poorly-suited to this task.

LLVM's graph tools are meant to work with any kind of graph that you can throw at it. To achieve this, they are templated to the bone; the graph algorithms will work provided that you implement the simple `GraphTraits` interface that they use.

{% highlight c++ %}
template<>
struct llvm::GraphTraits<MyGraphType*>
{
	typedef MyGraphNode NodeType;
	typedef NodeType* NodeRef;
	typedef MyGraphNodeIterator ChildIteratorType;
	typedef MyGraphNodeIterator nodes_iterator;
	
	static NodeRef getEntryNode(MyGraphType* node);
	static nodes_iterator nodes_begin(MyGraphType* f);
	static nodes_iterator nodes_end(MyGraphType* f);
	static ChildIteratorType child_begin(NodeRef node);
	static ChildIteratorType child_end(NodeRef node);
};
{% endhighlight %}

With just that, you can get node traversal in just about any order that you like for you graph, fast dominator tree calculation, and a lot of other interesting things.

What you *don't* get: regions.

LLVM's `RegionInfoBase` base class, which performs all the heavy lifting of finding regions, has a private constructor, a private destructor, and private fields for the analyses that it needs. Its two concrete subclasses are friended into the class definition, and they manipulate these private fields themselves, locking out everyone else for reasons that I can't quite discern.

Because of the private constructor and destructor, there is no standard-compliant way to inherit from `RegionInfoBase` without modifying its definition to either make these members `protected` upstream, or sinfully violate the one-definition rule in a way or another. I received [no response][3] when I asked if it was meant to be subclassed on the llvm-dev mailing list.

I went with it anyway, at least to give it a shot. To work around these limitations, I violated ODR in the nastiest way.

{% highlight c++ %}
// I know that this is nasty and violates ODR, but I don't know what else
// to do. RegionInfoBase has a private constructor and destructor, which
// makes it impossible to create a subclass that is not friended in. This
// macro is ugly enough that we will most likely know right away if it
// expands in unexpected locations.
class PreAstRegionInfo;
#define MachineRegionInfo MachineRegionInfo; \
	friend class ::PreAstRegionInfo
#include <llvm/Analysis/RegionInfo.h>
#undef MachineRegionInfo
{% endhighlight %}

This macro "friends us in" to `RegionInfo`. It "works" because `MachineRegionInfo` is used exactly once, when it is friended to `RegionInfo`.

Advancing, even using the default implementation of region graph traits turned out to be problematic. Heterogeneous iteration of region members (both regions and basic blocks) using `RegionInfo::element_begin` relies on the region's graph traits, which, for whatever reason, systematically crashed on use. As they are heavily templated and rely on macros, finding out the reason turned out to be more effort than I was interested in expending.

I looked for examples of this in the LLVM codebase. As it turns out, its *only* `RegionPass` is the `StructurizeCFG` pass. The `RegionInfoPass`, which is an analysis rather than a pass model, is used by a single pass to print regions. When things don't work as expected, it's hard to find examples of the right thing to do.

## The Good Old Ways

As a team of one and just a few hours a week to put on the project, I am not particularly interested in breaking new grounds around API usage. I finally decided to go back and own the region finding code instead of relying on LLVM to do it. It still mostly uses the same logic as LLVM's region detection code, with a handful of tweaks. Instead of producing regions, it queues a list of visited blocks, and folds blocks belonging to regions, when it identifies them, into a single block until you have just one block left that represents the whole function. I do think that the code is better and faster now, so there's that.

Hopefully, I won't feel the need to re-revisit this for a while. At the time of writing, this development is happening in the `structurize-v2` branch of fcd, which hasn't been merged to `master` yet. There are still a number of small things that need some love; the upgrade introduced a number of regressions in condition simplification. Progress is being made, however, and the merge will probably happen shortly.

 [1]: {% post_url 2016-02-17-structuring %}
 [2]: {% post_url 2016-02-24-seseloop %}
 [3]: http://lists.llvm.org/pipermail/llvm-dev/2016-November/107372.html
 [4]: http://www.ioccc.org
 [5]: https://users.ece.cmu.edu/~dbrumley/pdf/Lee,%20Avgerinos,%20Brumley_2011_TIE%20Principled%20Reverse%20Engineering%20of%20Types%20in%20Binary%20Programs.pdf
 