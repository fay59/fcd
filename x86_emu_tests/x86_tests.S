//
//  x86_tests.S
//  x86Emulator
//
//  Created by Félix on 2015-04-26.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

.section __TEXT,__text,regular,pure_instructions
.macosx_version_min 10, 10
.align	4, 0x90

.globl _x86_native_trampoline
.globl _x86_native_trampoline_call_ret
_x86_native_trampoline:
	push	rbp
	mov		rbp, rsp
	mov		qword ptr [rbp-8], rsp
	mov		rsp, r9
	call	r8

_x86_native_trampoline_call_ret:
	mov		rsp, qword ptr [rbp-8]
	leave
	ret

#define DECLARE_TEST(x) .globl _x86_test_ ## x
#include "x86_tests.h"

#define TEST(x) _x86_test_ ## x
#define SUB(x, y) x86_test_sub_ ## x ## _ ## y
#define END_TEST()	jmp		_x86_test_epilogue

.globl _x86_test_epilogue
_x86_test_epilogue:
	pushf
	pop		cx
	mov		qword ptr [rdi], rax
	mov		word ptr [rsi], cx

	# zero location used with pushf before returning
	xor		rax, rax
	mov		word ptr [rsp-2], ax
	ret

TEST(adc32):
	mov		eax, edx
	stc
	adc		eax, ecx
END_TEST()

TEST(adc64):
	mov		rax, rdx
	stc
	adc		rax, rcx
END_TEST()

TEST(and32):
	mov		eax, edx
	and		eax, ecx
END_TEST()

TEST(and64):
	mov		rax, rdx
	and		rax, rcx
END_TEST()

TEST(bt):
	xor		rax, rax
	bt		rdx, rcx
END_TEST()

TEST(call):
	sub		rsp, 8
	call	SUB(call, target)
	add		rsp, 8
END_TEST()

SUB(call, target):
	mov		rax, qword ptr [rsp]
	ret

TEST(cdq):
	mov		rax, rdx
	cdq
	mov		rax, rdx
END_TEST()

TEST(cdqe):
	mov		rax, rdx
	cdqe
END_TEST()

TEST(cmov):
	xor		rax, rax
	cmove	rax, rdx
	test	rax, rax
	cmove	rax, rcx
END_TEST()

TEST(cmp):
	xor		rax, rax
	cmp		rdx, rcx
END_TEST()

TEST(cqo):
	mov		rax, rdx
	cqo
	mov		rax, rdx
END_TEST()

TEST(dec):
	xor		rax, rax
	add		rax, 1
	stc
	mov		rax, rdx
	dec		rax
END_TEST()

TEST(idiv16_quotient):
	mov		ax, dx
	idiv	cl
	movzx	rax, al
END_TEST()

TEST(idiv16_remainder):
	mov		ax, dx
	idiv	cl
	mov		al, ah
	movzx	rax, al
END_TEST()

TEST(idiv128_quotient):
	mov		rax, rdx
	cqo
	idiv	rcx
	mov		rax, rdx
END_TEST()

TEST(idiv128_remainder):
	mov		rax, rdx
	cqo
	idiv	rcx
END_TEST()

TEST(imul32):
	xor		rax, rax
	mov		eax, edx
	imul	eax, ecx
END_TEST()

TEST(imul64):
	xor		rax, rax
	mov		rax, rdx
	imul	rax, rcx
END_TEST()

TEST(imul128):
	xor		rax, rax
	mov		rax, rdx
	imul	rcx
	// We're gonna have to go with a checksum since we can't test 2 registers with this test harness.
	pushf
	add		rax, rdx
	popf
END_TEST()

TEST(inc):
	xor		rax, rax
	add		rax, 1
	stc
	mov		rax, rdx
	inc		rax
END_TEST()

TEST(j):
	xor		rax, rax
	stc
	jc		SUB(j, epilogue)
	add		rax, 1
	
	SUB(j, epilogue):
END_TEST()

TEST(jcxz):
	mov		ecx, 2
	jrcxz	SUB(jcxz, epilogue)
	sub		ecx, 1
	jecxz	SUB(jcxz, epilogue)
	sub		ecx, 1
	jrcxz	SUB(jcxz, epilogue)
	sub		ecx, 1

	SUB(jcxz, epilogue):
		mov		rax, rcx
END_TEST()

TEST(lea):
	lea		rax, word ptr [rdx + rcx * 2 + 60]
END_TEST()

TEST(leave):
	mov		rax, rbp
	mov		rbp, rdx
	push	rbp
	mov		rbp, rsp
	push	rcx
	push	rdx
	leave
	mov		rbp, rax
	ret

TEST(mov8):
	xor		rax, rax
	sub		rax, 1
	mov		al, dl
END_TEST()

TEST(mov16):
	xor		rax, rax
	sub		rax, 1
	mov		ax, dx
END_TEST()

TEST(mov32):
	xor		rax, rax
	sub		rax, 1
	mov		eax, edx
END_TEST()

TEST(mov64):
	mov		rax, rdx
END_TEST()

TEST(movzx8_16):
	xor		rax, rax
	sub		rax, 1
	movzx	ax, dl
END_TEST()

TEST(movzx16_64):
	xor		rax, rax
	sub		rax, 1
	movzx	rax, dx
END_TEST()

TEST(movsx):
	movsx	eax, dl
END_TEST()

TEST(movsxd):
	movsxd	rax, edx
END_TEST()

TEST(mul32):
	mov		rax, rdx
	mul		cx
	pushf
	add		rax, rdx
	popf
END_TEST()

TEST(mul64):
	mov		rax, rdx
	mul		ecx
	pushf
	add		rax, rdx
	popf
END_TEST()

TEST(mul128):
	mov		rax, rdx
	mul		rcx
	pushf
	add		rax, rdx
	popf
END_TEST()

TEST(neg):
	mov		rax, rdx
	neg		rax
END_TEST()

TEST(not):
	mov		rax, rdx
	not		rax
END_TEST()

TEST(or):
	mov		rax, rdx
	or		rax, rcx
END_TEST()

TEST(pop):
	sub		rsp, 8
	mov		qword ptr [rsp], rdx
	pop		rax
	sub		rsp, 8
	not		rdx
	mov		qword ptr [rsp], rdx
	add		rsp, 8
END_TEST()

TEST(push):
	push	rdx
	mov		rax, qword ptr [rsp]
	add		rsp, 8
END_TEST()

TEST(ror1):
	add		rcx, 1
	mov		rax, rdx
	ror		rax, 1
END_TEST()

TEST(ror):
	xor		rax, rax
	add		rax, 1
	mov		rax, rdx
	ror		rax, cl
END_TEST()

TEST(sar1):
	add		rcx, 1
	mov		rax, rdx
	sar		rax, 1
END_TEST()

TEST(sar):
	xor		rax, rax
	add		rax, 1
	mov		rax, rdx
	sar		rax, cl
END_TEST()

TEST(sbb32):
	mov		eax, edx
	stc
	sbb		eax, ecx
END_TEST()

TEST(sbb64):
	mov		rax, rdx
	stc
	sbb		rax, rcx
END_TEST()

TEST(seta):
	xor		rax, rax
	cmp		rdx, rcx
	seta	al
END_TEST()

TEST(setae):
	xor		rax, rax
	cmp		rdx, rcx
	setae	al
END_TEST()

TEST(setb):
	xor		rax, rax
	cmp		rdx, rcx
	setb	al
END_TEST()

TEST(setbe):
	xor		rax, rax
	cmp		rdx, rcx
	setbe	al
END_TEST()

TEST(sete):
	xor		rax, rax
	cmp		rdx, rcx
	sete	al
END_TEST()

TEST(setg):
	xor		rax, rax
	cmp		rdx, rcx
	setg	al
END_TEST()

TEST(setge):
	xor		rax, rax
	cmp		rdx, rcx
	setge	al
END_TEST()

TEST(setl):
	xor		rax, rax
	cmp		rdx, rcx
	setl	al
END_TEST()

TEST(setle):
	xor		rax, rax
	cmp		rdx, rcx
	setle	al
END_TEST()

TEST(setne):
	xor		rax, rax
	cmp		rdx, rcx
	setne	al
END_TEST()

TEST(setno):
	xor		rax, rax
	cmp		rdx, rcx
	setno	al
END_TEST()

TEST(setnp):
	xor		rax, rax
	cmp		rdx, rcx
	setnp	al
END_TEST()

TEST(setns):
	xor		rax, rax
	cmp		rdx, rcx
	setns	al
END_TEST()

TEST(seto):
	xor		rax, rax
	cmp		rdx, rcx
	seto	al
END_TEST()

TEST(setp):
	xor		rax, rax
	cmp		rdx, rcx
	setp	al
END_TEST()

TEST(sets):
	xor		rax, rax
	cmp		rdx, rcx
	sets	al
END_TEST()

TEST(shl1):
	add		rcx, 1
	mov		rax, rdx
	shl		rax, 1
END_TEST()

TEST(shl):
	xor		rax, rax
	add		rax, 1
	mov		rax, rdx
	shl		rax, cl
END_TEST()

TEST(shr1):
	add		rcx, 1
	mov		rax, rdx
	shr		rax, 1
END_TEST()

TEST(shr):
	xor		rax, rax
	add		rax, 1
	mov		rax, rdx
	shr		rax, cl
END_TEST()

TEST(stc):
	xor		rax, rax
	add		rax, 1
	stc
END_TEST()

TEST(sub32):
	mov		eax, edx
	sub		eax, ecx
END_TEST()

TEST(sub64):
	mov		rax, rdx
	sub		rax, rcx
END_TEST()

TEST(test):
	xor		rax, rax
	test	rdx, rcx
END_TEST()

TEST(xor):
	mov		rax, rdx
	xor		rax, rcx
END_TEST()
