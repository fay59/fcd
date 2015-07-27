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

epilogue:
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
	jmp		epilogue

TEST(adc64):
	mov		rax, rdx
	stc
	adc		rax, rcx
	jmp		epilogue

TEST(and32):
	mov		eax, edx
	and		eax, ecx
	jmp		epilogue

TEST(and64):
	mov		rax, rdx
	and		rax, rcx
	jmp		epilogue

TEST(call):
	sub		rsp, 8
	call	SUB(call, target)
	add		rsp, 8
	jmp		epilogue

	SUB(call, target):
		mov		rax, qword ptr [rsp]
		ret

TEST(cdq):
	mov		rax, rdx
	cdq
	mov		rax, rdx
	jmp		epilogue

TEST(cmov):
	xor		rax, rax
	cmove	rax, rdx
	test	rax, rax
	cmove	rax, rcx
	jmp		epilogue

TEST(cmp):
	xor		rax, rax
	cmp		rdx, rcx
	jmp		epilogue

TEST(cqo):
	mov		rax, rdx
	cqo
	mov		rax, rdx
	jmp		epilogue

TEST(dec):
	xor		rax, rax
	add		rax, 1
	stc
	mov		rax, rdx
	dec		rax
	jmp		epilogue

TEST(idiv16_quotient):
	mov		ax, dx
	idiv	cl
	movzx	rax, al
	jmp		epilogue

TEST(idiv16_remainder):
	mov		ax, dx
	idiv	cl
	mov		al, ah
	movzx	rax, al
	jmp		epilogue

TEST(idiv128_quotient):
	mov		rax, rdx
	cqo
	idiv	rcx
	mov		rax, rdx
	jmp		epilogue

TEST(idiv128_remainder):
	mov		rax, rdx
	cqo
	idiv	rcx
	jmp		epilogue

TEST(imul32):
	xor		rax, rax
	mov		eax, edx
	imul	eax, ecx
	jmp		epilogue

TEST(imul64):
	xor		rax, rax
	mov		rax, rdx
	imul	rax, rcx
	jmp		epilogue

TEST(inc):
	xor		rax, rax
	add		rax, 1
	stc
	mov		rax, rdx
	inc		rax
	jmp		epilogue

TEST(j):
	xor		rax, rax
	stc
	jc		SUB(j, epilogue)
	add		rax, 1
	
	SUB(j, epilogue):
		jmp		epilogue

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
		jmp		epilogue

TEST(lea):
	lea		rax, word ptr [rdx + rcx * 2 + 60]
	jmp		epilogue

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
    jmp		epilogue

TEST(mov16):
	xor		rax, rax
	sub		rax, 1
    mov		ax, dx
    jmp		epilogue

TEST(mov32):
	xor		rax, rax
	sub		rax, 1
    mov		eax, edx
    jmp		epilogue

TEST(mov64):
    mov		rax, rdx
    jmp		epilogue

TEST(movzx8_16):
	xor		rax, rax
	sub		rax, 1
	movzx	ax, dl
	jmp		epilogue

TEST(movzx16_64):
	xor		rax, rax
	sub		rax, 1
	movzx	rax, dx
	jmp		epilogue

TEST(movsx):
	movsx	eax, dl
	jmp		epilogue

TEST(movsxd):
	movsxd	rax, edx
	jmp		epilogue

TEST(not):
	mov		rax, rdx
	not		rax
	jmp		epilogue

TEST(or):
	mov		rax, rdx
	or		rax, rcx
	jmp		epilogue

TEST(pop):
	sub		rsp, 8
	mov		qword ptr [rsp], rdx
	pop		rax
	sub		rsp, 8
	not		rdx
	mov		qword ptr [rsp], rdx
	add		rsp, 8
	jmp		epilogue

TEST(push):
	push	rdx
	mov		rax, qword ptr [rsp]
	add		rsp, 8
	jmp epilogue

TEST(ror1):
	add		rcx, 1
	mov		rax, rdx
	ror		rax, 1
	jmp epilogue

TEST(ror):
	xor		rax, rax
	add		rax, 1
	mov		rax, rdx
	ror		rax, cl
	jmp		epilogue

TEST(sar1):
	add		rcx, 1
	mov		rax, rdx
	sar		rax, 1
	jmp epilogue

TEST(sar):
	xor		rax, rax
	add		rax, 1
	mov		rax, rdx
	sar		rax, cl
	jmp		epilogue

TEST(seta):
	xor		rax, rax
	cmp		rdx, rcx
	seta	al
	jmp epilogue

TEST(setae):
	xor		rax, rax
	cmp		rdx, rcx
	setae	al
	jmp epilogue

TEST(setb):
	xor		rax, rax
	cmp		rdx, rcx
	setb	al
	jmp epilogue

TEST(setbe):
	xor		rax, rax
	cmp		rdx, rcx
	setbe	al
	jmp epilogue

TEST(sete):
	xor		rax, rax
	cmp		rdx, rcx
	sete	al
	jmp epilogue

TEST(setg):
	xor		rax, rax
	cmp		rdx, rcx
	setg	al
	jmp epilogue

TEST(setge):
	xor		rax, rax
	cmp		rdx, rcx
	setge	al
	jmp epilogue

TEST(setl):
	xor		rax, rax
	cmp		rdx, rcx
	setl	al
	jmp epilogue

TEST(setle):
	xor		rax, rax
	cmp		rdx, rcx
	setle	al
	jmp epilogue

TEST(setne):
	xor		rax, rax
	cmp		rdx, rcx
	setne	al
	jmp epilogue

TEST(setno):
	xor		rax, rax
	cmp		rdx, rcx
	setno	al
	jmp epilogue

TEST(setnp):
	xor		rax, rax
	cmp		rdx, rcx
	setnp	al
	jmp epilogue

TEST(setns):
	xor		rax, rax
	cmp		rdx, rcx
	setns	al
	jmp epilogue

TEST(seto):
	xor		rax, rax
	cmp		rdx, rcx
	seto	al
	jmp epilogue

TEST(setp):
	xor		rax, rax
	cmp		rdx, rcx
	setp	al
	jmp epilogue

TEST(sets):
	xor		rax, rax
	cmp		rdx, rcx
	sets	al
	jmp epilogue

TEST(shl1):
	add		rcx, 1
	mov		rax, rdx
	shl		rax, 1
	jmp epilogue

TEST(shl):
	xor		rax, rax
	add		rax, 1
	mov		rax, rdx
	shl		rax, cl
	jmp		epilogue

TEST(shr1):
	add		rcx, 1
	mov		rax, rdx
	shr		rax, 1
	jmp epilogue

TEST(shr):
	xor		rax, rax
	add		rax, 1
	mov		rax, rdx
	shr		rax, cl
	jmp		epilogue

TEST(stc):
	xor		rax, rax
	add		rax, 1
	stc
	jmp		epilogue

TEST(sub32):
	mov		eax, edx
	sub		eax, ecx
	jmp		epilogue

TEST(sub64):
	mov		rax, rdx
	sub		rax, rcx
	jmp		epilogue

TEST(test):
	xor		rax, rax
	test	rdx, rcx
	jmp		epilogue

TEST(xor):
	mov		rax, rdx
	xor		rax, rcx
	jmp		epilogue
