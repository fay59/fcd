---
layout: post
title:  "Using fcd to solve the CSAW Wyvern challenges"
date:   2016-02-21 14:46:45 -0500
---

One of fcd's touted abilities is to simplify code before presenting its pseudo-C
output. This can be extremely helpful to reverse engineer obfuscated programs. A
good showcase would be the CSAW 2015 *Wyvern* challenges.

The qualification round featured a first instalment, and the finals saw a
second episode. Both challenges were rated at 500 points, the highest score for
an individual challenge at the CSAW CTF. This blog post focuses on the first
wyvern challenge.

<ul class="button-row-post">
	<li>
		<a href="{{ "/files/csaw-wyvern-9949023fee353b66a70c56588540f0ec2c3531ac" | prepend: site.baseurl }}">
			<i class="fa fa-download"></i>
			Download csaw-wyvern
		</a>
	</li>
</ul>

Starting up the program shows this message:

	+-----------------------+
	|    Welcome Hero       |
	+-----------------------+

	[!] Quest: there is a dragon prowling the domain.
		brute strength and magic is our only hope. Test your skill.

	Enter the dragon's secret:

Of course, running `strings` over `wyvern` won't have any useful output. The
next logical step is to hand it to a disassembler, like `objdump`. However, the
result is an absolute catastrophe. Every symbol worth inspecting (and most that
aren't even worth it too) are overrun with code branching off at very random
points:

    $ objdump -M intel -d csaw-wyvern2 
    [snip]
	00000000004014b0 <_Z15transform_inputSt6vectorIiSaIiEE>:
	  4014b0:	55                   	push   rbp
	  4014b1:	48 89 e5             	mov    rbp,rsp
	  4014b4:	53                   	push   rbx
	  4014b5:	48 83 ec 48          	sub    rsp,0x48
	[spurious branch code starts here]
	  4014b9:	8b 04 25 68 03 61 00 	mov    eax,DWORD PTR ds:0x610368
	  4014c0:	8b 0c 25 58 05 61 00 	mov    ecx,DWORD PTR ds:0x610558
	  4014c7:	89 c2                	mov    edx,eax
	  4014c9:	81 ea 01 00 00 00    	sub    edx,0x1
	  4014cf:	0f af c2             	imul   eax,edx
	  4014d2:	25 01 00 00 00       	and    eax,0x1
	  4014d7:	3d 00 00 00 00       	cmp    eax,0x0
	  4014dc:	40 0f 94 c6          	sete   sil
	  4014e0:	81 f9 0a 00 00 00    	cmp    ecx,0xa
	  4014e6:	41 0f 9c c0          	setl   r8b
	  4014ea:	44 08 c6             	or     sil,r8b
	  4014ed:	40 f6 c6 01          	test   sil,0x1
	  4014f1:	48 89 7d f0          	mov    QWORD PTR [rbp-0x10],rdi
	  4014f5:	0f 85 05 00 00 00    	jne    401500 <_Z15transform_inputSt6vec
    [snip]

The condition resolves to something like `((x * (x - 1)) & 0x1) == 0 || y < 10`.
Folks lucky enough to have Hex-Rays can see that the program has been completely
drowned in them, to the point where there is rarely (if ever) more than one
useful instruction between each block of 14 garbage instructions. This obscures
the control flow a great deal.

During the qualifications, Ryan Stortz said through his
{% include icon-twitter.html username="withzombies" %} Twitter account that the
first instalment would be best dealt using dynamic analysis. Most teams (mine
not included) used [Intel's PIN][1] to instrument the code and figure out the
input that makes the program run for the longest time. I'm not sure what people
did for the second round; since fcd couldn't deal with programs that big this
last November, I ended up erasing the nasty conditions by hand until the code
made sense. The exercise was as tedious as it sounds, and the sleep deprivation
certainly didn't help.

Fast-forward about three months later. Fcd is still not the best decompiler
available, but it certainly can handle this odd job.

## Fighting dragons with dragons

A major strength of fcd, especially when compared to other decompilers, is that
users can write optimization passes in Python to supplement the standard LLVM
passes to simplify program code. LLVM is excellent at finding code with a
constant outcome, deleting useless bits and simplifying the rest, so we can
focus on creating a tiny pass that will tip the garbage code just over the edge
of unpredictability into predictability, and let the framework do *all* the
heavy lifting.

In this case, for both instalments, the variables used in the conditions are
loaded from the data segment, but they are never modified. This means that they
are always equal to zero. We can share this knowledge with fcd using a tiny
optimization pass written in Python.

If you're actually doing the challenge, you first need to identify interesting
functions. This is more an fcd demo than a Wyvern write-up, so you'll have to
bear with me. After some manual inspection or dynamic analysis, you should
figure out that the interesting functions are `sanitize_input` (0x401cc0) and
`transform_input` (0x4014b0), which transform and test the input line in
mysterious ways.

For this example, we'll do two invocations of fcd: one to save a LLVM assembly
file corresponding to the executable (because generating this file takes a long
time), and one to run fcd's optimization passes (and our custom pass) over it.
First generating an assembly file will save us lots of time if we screw up our
custom pass.

    $ fcd -p -n -e 0x4014b0 -e 0x401cc0 wyvern > wyvern.ll

The [manual][2] goes into greater depth about these options, but the gist is the
following:

* `-p` ("partial") tells fcd that we're interested in a few functions only;
* `-e` ("entry") specifies the virtual addresses of the functions that we're
	interested with;
* `-n` says that we want a LLVM assembly file for output.

This takes some time (about 20 seconds on my computer). It's actually nothing
compared to `wyvern2`, which takes about 7 minutes (though it still seems to
work). To my poor 2011 MacBook Pro's defence, I compile fcd against a debug LLVM
build, which can be up to 10 times slower than a release build.

The next step will be to write a Python script to act as an optimization pass.
We can get away with just a little under 40 lines.

Looking at the assembly code above, we see that the obfuscated code loads two
values (that are known to be zero), manipulates them a little bit and branches
off. LLVM is powerful enough that if we can only tell it that the loaded values
are always zero, it should be able to get rid of everything else. This is what
we'll do here.

Running `nm wyvern2 | sort`, we can see that all the `x` and `y` variables all
live between the addresses 0x610318 and 0x6105ac (inclusively). The x86
instructions that load from them are `mov` instructions, which eventually
translate to LLVM [`load` instructions][3]. We will build our pass to replace
`load` LLVM instructions to these addresses with a constant zero value.

Optimization scripts need a `passName` variable, and either a `runOnFunction` or
a `runOnModule` global function. This should come at no surprise to people
remotely familiar with LLVM's pass infrastructure. In our case, we only ever
need to access individual functions, so that's what we'll use.

Our pass will essentially go as:

{% highlight python %}
from llvm import *

passName = "Wyvern cleanup"

def runOnFunction(func):
	changed = False
	bb = func.GetFirstBasicBlock()
	while bb != None:
		changed |= _runOnBB(bb)
		bb = bb.GetNextBasicBlock()
	return changed

def _runOnBB(bb):
	changed = False
	inst = bb.GetFirstInstruction()
	while inst != None:
		changed |= _runOnInst(inst)		
		inst = inst.GetNextInstruction()
	return changed

def _runOnInst(inst):
	if inst.GetInstructionOpcode() != Opcode.Load:
		return False
	
	cAddress = inst.GetOperand(0).IsAConstantExpr()
	if cAddress == None or cAddress.GetConstOpcode() != Opcode.IntToPtr:
		return False
	
	constantInt = cAddress.GetOperand(0).IsAConstantInt()
	if constantInt == None:
		return False
	
	address = constantInt.ConstIntGetZExtValue()
	if address < 0x610318 or address > 0x6105ac: # x and y variables
		return False
	
	zero = inst.TypeOf().ConstInt(0, False)
	inst.ReplaceAllUsesWith(zero)
	return True
{% endhighlight %}

The `runOnFunction` function is run when the wrapper LLVM pass is executed. It
must return `True` if the pass modified the function. It simply takes every
basic block in the function and passes it to `_runOnBasicBlock`.
`_runOnBasicBlock`, on its end, iterates over every instruction in the basic
block and passes them to `_runOnInst`.

The `_runOnInst` function checks if the current instruction is a `load`
instruction that loads from the address of a `x` or `y` variable. If so, it
replaces every use of the `load`ed value with the constant zero value. And just
with that, the other optimization passes will correctly detect that the
conditions have a constant outcome, and constant propagation will eat them away.

We can use our Python pass (saved as a `wyvern.py` file) with this invocation of
fcd:

    $ fcd -m --cc=x86_64/sysv -O wyvern.py wyvern.ll

This time around, the options mean:

* `-m`: the input file is a LLVM module;
* `--cc=x86_64/sysv`: since the input is a LLVM module, fcd can't gather enough
	metadata to guess the calling convention, so we need to specify that the
	program uses the System V x86_64 calling convention;
* `-O wyvern.py` tells fcd to load the wyvern.py file as an optimization pass.

This generates pseudocode that is hopefully analyzable.

## Using brute strength and magic

The output, **passed through `c++filt` for convenience**, looks like:

{% highlight c %}
{int64_t} transform_input(std::vector<int, std::allocator<int> >)(int64_t rip, int64_t rdi)
{
	int32_t* anon41;
	int32_t* anon37;
	int32_t anon36;
	bool anon18;
	int64_t anon16;
	int64_t phi11;
	int64_t phi10;
	int32_t* anon6;
	int32_t* anon5;
	{int32_t, int8_t[12], int32_t, int8_t[32], int32_t, int8_t[3], int8_t, int8_t, int8_t, int8_t, int8_t, int64_t, int32_t*, int32_t*, int8_t[7], int8_t, int64_t, int8_t[16], int64_t} stackframe;

	stackframe.field18 = rip;
	stackframe.field16 = rdi;
	stackframe.field15 = 1;
	anon5 = &stackframe.field2;
	anon6 = &stackframe.field0;
	stackframe.field2 = 0;
	stackframe.field0 = 0;
	stackframe.field13 = anon5;
	stackframe.field12 = anon6;
	phi10 = rdi;
	while (true)
	{
		stackframe.field11 = (__sext int64_t)stackframe.field0;
		anon16 = std::vector<int, std::allocator<int> >::size() const(4200087, phi10).rax;
		anon18 = stackframe.field11 < anon16;
		stackframe.field10 = (__zext int8_t)anon18;
		stackframe.field9 = 1;
		if (!anon18)
			break;
		else
		{
			anon36 = *(int32_t*)std::vector<int, std::allocator<int> >::operator[](unsigned long)(4200418, stackframe.field16, (__sext int64_t)*stackframe.field12).rax;
			anon37 = stackframe.field13;
			*anon37 = anon36 + *anon37;
			stackframe.field8 = 1;
			anon41 = stackframe.field12;
			*anon41 = *anon41 + 1;
			stackframe.field7 = 1;
			phi10 = stackframe.field16;
			phi11 = phi11 & -256 | 1;
		}
	}
	stackframe.field6 = 1;
	return {(__zext int64_t)*stackframe.field13};
}
{} sanitize_input(std::basic_string<char, std::char_traits<char>, std::allocator<char> >)(int64_t rip, int64_t rdi)
{
	int64_t anon171;
	int32_t anon159;
	int32_t* anon157;
	bool anon150;
	int32_t anon148;
	int32_t anon144;
	int64_t anon142;
	int64_t anon138;
	int64_t phi135;
	int32_t phi134;
	int32_t anon133;
	int64_t anon117;
	int32_t anon110;
	int64_t anon105;
	int64_t anon102;
	int32_t* anon93;
	int64_t anon90;
	int32_t anon81;
	int32_t* anon75;
	int8_t anon74;
	int64_t anon71;
	int64_t anon64;
	bool anon56;
	int64_t anon48;
	int64_t anon45;
	int64_t anon44;
	int64_t phi41;
	int64_t phi40;
	int64_t phi39;
	int32_t* phi38;
	int32_t phi37;
	int32_t* anon36;
	int32_t** anon33;
	int32_t** anon30;
	int32_t** anon28;
	int32_t** anon26;
	int32_t** anon23;
	int64_t anon21;
	int64_t anon20;
	int64_t anon18;
	int64_t anon8;
	{int8_t[16], int8_t[32], int8_t[16], int8_t[16], int8_t[16], int8_t[16], int8_t[16], int8_t[32], int8_t[84], int32_t, int64_t, int8_t[2], int8_t, int8_t, int8_t, int8_t, int8_t, int8_t[41], int64_t, int64_t, int32_t, int8_t[2], int8_t, int8_t, int32_t, int8_t[3], int8_t, int32_t, int8_t[3], int8_t, int32_t*, int64_t, int8_t[6], int8_t, int8_t, int64_t, int8_t[7], int8_t, int64_t, int8_t[7], int8_t, int64_t, int8_t[7], int8_t, int64_t, int8_t[6], int8_t, int8_t, int64_t, int32_t*, int64_t, int32_t*, int32_t*, int32_t*, int64_t, int32_t*, int64_t, int8_t[7], int8_t, int64_t, int8_t[48], int64_t}* anon1;
	{int8_t[16], int8_t[32], int8_t[16], int8_t[16], int8_t[16], int8_t[16], int8_t[16], int8_t[32], int8_t[84], int32_t, int64_t, int8_t[2], int8_t, int8_t, int8_t, int8_t, int8_t, int8_t[41], int64_t, int64_t, int32_t, int8_t[2], int8_t, int8_t, int32_t, int8_t[3], int8_t, int32_t, int8_t[3], int8_t, int32_t*, int64_t, int8_t[6], int8_t, int8_t, int64_t, int8_t[7], int8_t, int64_t, int8_t[7], int8_t, int64_t, int8_t[7], int8_t, int64_t, int8_t[6], int8_t, int8_t, int64_t, int32_t*, int64_t, int32_t*, int32_t*, int32_t*, int64_t, int32_t*, int64_t, int8_t[7], int8_t, int64_t, int8_t[48], int64_t} stackframe;

	anon1 = &stackframe;
	stackframe.field61 = rip;
	stackframe.field59 = rdi;
	stackframe.field58 = 1;
	anon8 = (int64_t)&stackframe.field7;
	anon18 = (int64_t)&stackframe.field2;
	anon20 = (int64_t)&stackframe.field1;
	anon21 = (int64_t)anon1;
	stackframe.field56 = (int64_t)&stackframe.field4;
	anon23 = &stackframe.field55;
	*(int64_t*)anon23 = (int64_t)&stackframe.field8;
	stackframe.field54 = anon8;
	anon26 = &stackframe.field53;
	*(int64_t*)anon26 = (int64_t)&stackframe.field6;
	anon28 = &stackframe.field52;
	*(int64_t*)anon28 = (int64_t)&stackframe.field5;
	anon30 = &stackframe.field51;
	*(int64_t*)anon30 = anon21;
	stackframe.field50 = (int64_t)&stackframe.field3;
	anon33 = &stackframe.field49;
	*(int64_t*)anon33 = anon18;
	stackframe.field48 = anon20;
	std::vector<int, std::allocator<int> >::vector()(4202028, anon8);
	anon36 = stackframe.field53;
	*anon36 = 0;
	phi37 = 0;
	phi38 = anon36;
	phi39 = anon21;
	phi40 = anon20;
	phi41 = anon18;
	while (true)
	{
		anon44 = (__sext int64_t)*(int32_t*)6357304 >> 2;
		anon45 = (__zext int64_t)phi37;
		anon48 = anon45 - (anon44 & 4294967295);
		anon56 = (anon48 & 2147483648) > 2147483647 ^ ((anon48 ^ anon45) & (__zext int64_t)((int32_t)anon44 ^ phi37)) > 2147483647;
		stackframe.field47 = (__zext int8_t)anon56;
		if (!anon56)
			break;
		else
		{
			stackframe.field46 = 1;
			anon64 = (__sext int64_t)phi38;
			stackframe.field44 = anon64;
			stackframe.field43 = 1;
			anon71 = std::basic_string<char, std::char_traits<char>, std::allocator<char> >::operator[](unsigned long)(stackframe.field59, anon64, 4294967295, 0).rax;
			stackframe.field41 = anon71;
			anon74 = *(int8_t*)anon71;
			anon75 = stackframe.field52;
			*anon75 = (__sext int32_t)anon74;
			std::vector<int, std::allocator<int> >::push_back(int const&)(4203204, stackframe.field54, (int64_t)anon75);
			stackframe.field40 = 1;
			anon81 = *stackframe.field53;
			*stackframe.field49 = anon81;
			stackframe.field38 = (__sext int64_t)anon81;
			stackframe.field37 = 1;
			anon90 = std::basic_string<char, std::char_traits<char>, std::allocator<char> >::length() const(stackframe.field59).rax;
			stackframe.field35 = anon90;
			stackframe.field34 = 1;
			anon93 = stackframe.field49;
			*anon93 = (int32_t)(anon90 >> 40 & stackframe.field38 | 28);
			stackframe.field33 = 1;
			anon102 = (__sext int64_t)*stackframe.field53;
			stackframe.field31 = anon102;
			anon105 = std::vector<int, std::allocator<int> >::operator[](unsigned long)(4204345, 6357752, anon102).rax;
			*(int64_t*)&stackframe.field30 = anon105;
			stackframe.field29 = 1;
			anon110 = *(int32_t*)anon105;
			stackframe.field27 = anon110;
			std::vector<int, std::allocator<int> >::vector(std::vector<int, std::allocator<int> > const&)(4204666, anon112, stackframe.field54);
			stackframe.field26 = 1;
			anon117 = transform_input(std::vector<int, std::allocator<int> >)(4205093, stackframe.field48).rax;
			stackframe.field24 = (int32_t)anon117;
			stackframe.field23 = (__zext int8_t)(((__zext int64_t)stackframe.field27 - anon117 & 4294967295) == 0);
			std::vector<int, std::allocator<int> >::~vector()(4205409, stackframe.field48);
			stackframe.field22 = 1;
			anon133 = *stackframe.field49;
			phi134 = anon133;
			phi135 = phi41 & -65281 | 256;
			if ((stackframe.field23 & 1) != 0)
			{
				anon138 = (__sext int64_t)*stackframe.field53;
				stackframe.field19 = anon138;
				anon142 = std::vector<int, std::allocator<int> >::operator[](unsigned long)(4205898, 6357752, anon138).rax;
				stackframe.field18 = anon142;
				anon144 = anon133;
				anon148 = (*(int32_t*)anon142 & anon144) >> 31;
				*stackframe.field49 = anon148;
				phi134 = anon148;
				phi135 = 4294902271;
			}
			anon150 = phi134 != 0;
			stackframe.field16 = (__zext int8_t)anon150;
			stackframe.field15 = 1;
			if (anon150)
				break;
			else
			{
				stackframe.field13 = 1;
				anon157 = stackframe.field53;
				anon159 = *anon157 + 1;
				*anon157 = anon159;
				phi37 = anon159;
				phi38 = stackframe.field53;
				phi39 = phi39 & -65281 | 256;
				phi40 = phi40 & -65281 | 256;
				phi41 = phi135 & -65281 | 256;
			}
		}
	}
	if (phi59 != 0)
	{
		stackframe.field14 = 1;
		*stackframe.field55 = *stackframe.field53 << 8 & 256;
		*stackframe.field51 = 1;
	}
	else
	{
		stackframe.field12 = 1;
		anon171 = std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)(6357472, 4253236, 4294967295, 0).rax;
		stackframe.field10 = anon171;
		*stackframe.field55 = 4919;
		*stackframe.field51 = 1;
	}
	std::vector<int, std::allocator<int> >::~vector()(4208905, stackframe.field54);
	return {};
}
{% endhighlight %}

What hurts the most in the output is that fcd's alias analysis (which is mostly
LLVM's alias analysis) isn't smart enough to figure out that a lot of these
functions don't modify any memory. If we could help fcd understand that
`vector::size()` and `vector::operator[]` don't modify memory, LLVM's *scalar
replacement of aggregates* pass should be able, among other things, to promote
`transform_input`'s `stackframe` variable to SSA values. This would eliminate
the pointer indirections and make the function a whole lot more readable.
Unfortunately, there's currently no way to do that, so we're stuck with the
pointer-happy versions of the functions.

Still, `transform_input` isn't particularly hard to analyze. There's a loop that
tests if what's in `field0` is smaller than the size of the vector pointed to by
`phi10` (`rdi`); else, the loop breaks. If `field0` is indeed smaller than the
vector's size, we use `operator[]` with `field0` as the index to get a pointer
to the element in the vector (as this is how references translate), and then we
load that value and accumulate it in `field9`. We increment the loop counter by
hand.

In other words, `transform_input` might originally have looked like this:

{% highlight c++ %}
int transform_input(std::vector<int> vec)
{
	int sum = 0;
	for (int i = 0; i < vec.size(); ++i)
		sum += vec[i];
	return sum;
}
{% endhighlight %}

Maybe fcd will one day output something that good! Until then, a little bit of
analysis is still required.

`sanitize_input` is unfortunately much more cluttered. The stack frame is much
larger and stack recovery didn't figure out every stack pointer access, and now
we're stuck with strange pointer arithmetic based off `stackframe` fields. There
are several dead stores, and there are rampant double indirections that we
manually have to take care of. Several of these issues could be dealt with if
`transform_input` and `sanitize_input` were on a different optimization pipeline
(or if we just ran `fcd` twice with different optimizations), but the pass
pipeline is not very configurable without doing some source editing, so we will
have to deal with this.

The loop body looks quite bad and the simplest way to analyze it is probably to
look at the calls it makes and then thread them together.

{% highlight c++ %}
anon71 = std::basic_string<char, std::char_traits<char>, std::allocator<char> >::operator[](unsigned long)(stackframe.field59, anon64, 4294967295, 0).rax;
{% endhighlight %}

First, it uses `operator[]`. Field59 is the function's first parameter and
anon64 is the loop's index. That would be `arg0[i]`, in other words.

{% highlight c++ %}
std::vector<int, std::allocator<int> >::push_back(int const&)(4203204, stackframe.field54, (int64_t)anon75);
{% endhighlight %}

Next, it calls `push_back` with `field54` (aka `anon8`) as the vector
(constructed earlier), and the result of `operator[]` as the parameter (through
`anon75`), which is the value loaded from the pointer returned by the previous
call. In other words, it took `arg0[i]` and appended it to the vector.

{% highlight c++ %}
anon90 = std::basic_string<char, std::char_traits<char>, std::allocator<char> >::length() const(stackframe.field59).rax;
{% endhighlight %}

After that, it gets the string parameter's length.

{% highlight c++ %}
anon105 = std::vector<int, std::allocator<int> >::operator[](unsigned long)(4204345, 6357752, anon102).rax;
{% endhighlight %}

This uses `operator[]` on the global vector at address 0x6102f8. Its symbol name
is *hero*. It is built earlier and it is the concatenation of all the `secret*`
global variables in the program.

The index parameter is quite the aliasing maze. `anon102` is an index loaded by
dereferencing `field53`. The pointer is set to point to `field6`. It is not
used directly, but it is then set to zero through `*anon36` at the beginning of
the function. It's then referred to as `phi38` and it is incremented after each
successful loop iteration. In other words, it's also a (or the?) loop counter,
and each iteration of the loop gets the next number from the list of "secret"
values.

{% highlight c++ %}
std::vector<int, std::allocator<int> >::vector(std::vector<int, std::allocator<int> > const&)(4204666, anon112, stackframe.field54);
stackframe.field26 = 1;
anon117 = transform_input(std::vector<int, std::allocator<int> >)(4205093, stackframe.field48).rax;
stackframe.field24 = (int32_t)anon117;
stackframe.field23 = (__zext int8_t)(((__zext int64_t)stackframe.field27 - anon117 & 4294967295) == 0);
std::vector<int, std::allocator<int> >::~vector()(4205409, stackframe.field48);
stackframe.field22 = 1;
{% endhighlight %}

This copy-constructs a vector to be passed to `transform_input`. `anon112` is
the new vector's address and `field54` (the vector made out of the string
argument) as the vector being copied. It then calls `transform_input` on that
vector (summing all of its elements) and destroys the vector copy. It tests
whether `field27` (which contains the "hero" value for this iteration) is the
same as the vector's sum and saves that result in `field23`.

At this point, things get pretty messy and and walking back aliasing values is
no longer very useful. However, we've got a crucial piece of information: the
program tests that the sum of every character so far in the loop is equal to the
values of the hero vector.

## The dragon's secret

We've already talked about the `secret` variables in the program. Running
`nm wyvern | grep secret | sort`, we can have an ordered list of them.
Conveniently enough, the content of the `secret` variables is show directly in
their name, so `secret_1222` contains 1222.

	$ nm wyvern | grep secret | sort
	000000000061013c D secret_100
	0000000000610140 D secret_214
	0000000000610144 D secret_266
	0000000000610148 D secret_369
	000000000061014c D secret_417
	0000000000610150 D secret_527
	0000000000610154 D secret_622
	0000000000610158 D secret_733
	000000000061015c D secret_847
	0000000000610160 D secret_942
	0000000000610164 D secret_1054
	0000000000610168 D secret_1106
	000000000061016c D secret_1222
	0000000000610170 D secret_1336
	0000000000610174 D secret_1441
	0000000000610178 D secret_1540
	000000000061017c D secret_1589
	0000000000610180 D secret_1686
	0000000000610184 D secret_1796
	0000000000610188 D secret_1891
	000000000061018c D secret_1996
	0000000000610190 D secret_2112
	0000000000610194 D secret_2165
	0000000000610198 D secret_2260
	000000000061019c D secret_2336
	00000000006101a0 D secret_2412
	00000000006101a4 D secret_2498
	00000000006101a8 D secret_2575

The hypothesis is that at index N, the sum of the ASCII codes of the input
string should be equal to the corresponding `secret` variable. We can easily
write a tiny Python script to see what this would look like.

{% highlight python %}
sums = [100, 214, 266, 369, 417, 527, 622, 733, 847, 942, 1054, 1106, 1222,
	1336, 1441, 1540, 1589, 1686, 1796, 1891, 1996, 2112, 2165, 2260, 2336,
	2412, 2498, 2575]

string = ""
previous = 0
for sum in sums:
	string += chr(sum - previous)
	previous = sum

print string
{% endhighlight %}

The result is `dr4g0n_or_p4tric1an_it5_LLVM`, a string that suspiciously looks
like it could be the answer. We can test this by running `wyvern` and trying it.

	$ ./wyvern
	+-----------------------+
	|    Welcome Hero       |
	+-----------------------+

	[!] Quest: there is a dragon prowling the domain.
		brute strength and magic is our only hope. Test your skill.

	Enter the dragon's secret: dr4g0n_or_p4tric1an_it5_LLVM
	success

	[+] A great success! Here is a flag{dr4g0n_or_p4tric1an_it5_LLVM}

## Tending to your wounds

At this point, I feel that fcd did an excellent job at cleaning up spurious
branches with truly minimal effort. However, because of alias analysis problems,
it fell short of providing effortlessly analyzable output. Unfortunately, alias
analysis is known to be at least undecidable since the early nineties, so it's
unlikely that fcd will ever solve the General Problem.

That said, fcd is still a work in progress and development started less than a
year ago, with a team of one. Coming this close to beating the wyvern to a pulp
is very exciting and somewhat of a milestone.

So with this, I'll retreat from the battlefield, train some more, and maybe try
the fight again once I feel that relevant progress was made. Keep an eye open
for it!

  [1]: https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool
  [2]: {{ "/help/" | prepend: site.baseurl }}
  [3]: http://llvm.org/docs/LangRef.html#load-instruction
