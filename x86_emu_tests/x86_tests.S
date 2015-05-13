.section __TEXT,__text,regular,pure_instructions
.macosx_version_min 10, 10
.align	4, 0x90

epilogue:
    pushf
    pop		cx
    mov		qword ptr [rdi], rax
    mov		word ptr [rsi], cx
    ret

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

.globl _x86_test_adc32
_x86_test_adc32:
	mov		eax, edx
	stc
	adc		eax, ecx
	jmp		epilogue

.globl _x86_test_adc64
_x86_test_adc64:
	mov		rax, rdx
	stc
	adc		rax, rcx
	jmp		epilogue

.globl _x86_test_and32
_x86_test_and32:
	mov		eax, edx
	and		eax, ecx
	jmp		epilogue

.globl _x86_test_and64
_x86_test_and64:
	mov		rax, rdx
	and		rax, rcx
	jmp		epilogue

.globl _x86_test_call
_x86_test_call:
	sub		rsp, 8
	call	test_call
	add		rsp, 8
	jmp		epilogue

test_call:
	mov		rax, qword ptr [rsp]
	ret

.globl _x86_test_cmov
_x86_test_cmov:
	xor		rax, rax
	cmove	rax, rdx
	test	rax, rax
	cmove	rax, rcx
	jmp		epilogue

.globl _x86_test_cmp
_x86_test_cmp:
	xor		rax, rax
	cmp		rdx, rcx
	jmp		epilogue

.globl _x86_test_dec
_x86_test_dec:
	xor		rax, rax
	add		rax, 1
	stc
	mov		rax, rdx
	dec		rax
	jmp		epilogue

.globl _x86_test_imul32
_x86_test_imul32:
	xor		rax, rax
	mov		eax, edx
	imul	eax, ecx
	jmp		epilogue

.globl _x86_test_imul64
_x86_test_imul64:
	xor		rax, rax
	mov		rax, rdx
	imul	rax, rcx
	jmp		epilogue

.globl _x86_test_inc
_x86_test_inc:
	xor		rax, rax
	add		rax, 1
	stc
	mov		rax, rdx
	inc		rax
	jmp		epilogue

.globl _x86_test_j
_x86_test_j:
	xor		rax, rax
	stc
	jc		test_j_epilogue
	add		rax, 1
	
test_j_epilogue:
	jmp		epilogue

.globl _x86_test_jcxz
_x86_test_jcxz:
	mov		ecx, 2
	jrcxz	test_jcx_epilogue
	sub		ecx, 1
	jecxz	test_jcx_epilogue
	sub		ecx, 1
	jrcxz	test_jcx_epilogue
	sub		ecx, 1

test_jcx_epilogue:
	mov		rax, rcx
	jmp		epilogue

.globl _x86_test_lea
_x86_test_lea:
	lea		rax, word ptr [rdx + rcx * 2 + 60]
	jmp		epilogue

.globl _x86_test_leave
_x86_test_leave:
	mov		rax, rbp
	mov		rbp, rdx
	push	rbp
	mov		rbp, rsp
	push	rcx
	push	rdx
	leave
	mov		rbp, rax
	ret

.globl _x86_test_mov8
_x86_test_mov8:
	xor		rax, rax
	sub		rax, 1
    mov		al, dl
    jmp		epilogue

.globl _x86_test_mov16
_x86_test_mov16:
	xor		rax, rax
	sub		rax, 1
    mov		ax, dx
    jmp		epilogue

.globl _x86_test_mov32
_x86_test_mov32:
	xor		rax, rax
	sub		rax, 1
    mov		eax, edx
    jmp		epilogue

.globl _x86_test_mov64
_x86_test_mov64:
    mov		rax, rdx
    jmp		epilogue

.globl _x86_test_movzx8_16
_x86_test_movzx8_16:
	xor		rax, rax
	sub		rax, 1
	movzx	ax, dl
	jmp		epilogue

.globl _x86_test_movzx16_64
_x86_test_movzx16_64:
	xor		rax, rax
	sub		rax, 1
	movzx	rax, dx
	jmp		epilogue

.globl _x86_test_movsx
_x86_test_movsx:
	movsx	eax, dl
	jmp		epilogue

.globl _x86_test_movsxd
_x86_test_movsxd:
	movsxd	rax, edx
	jmp		epilogue

.globl _x86_test_not
_x86_test_not:
	mov		rax, rdx
	not		rax
	jmp		epilogue

.globl _x86_test_or
_x86_test_or:
	mov		rax, rdx
	or		rax, rcx
	jmp		epilogue

.globl _x86_test_pop
_x86_test_pop:
	sub		rsp, 8
	mov		qword ptr [rsp], rdx
	pop		rax
	sub		rsp, 8
	not		rdx
	mov		qword ptr [rsp], rdx
	add		rsp, 8
	jmp		epilogue

.globl _x86_test_push
_x86_test_push:
	push	rdx
	mov		rax, qword ptr [rsp]
	add		rsp, 8
	jmp epilogue

.globl _x86_test_ror1
_x86_test_ror1:
	add		rcx, 1
	mov		rax, rdx
	ror		rax, 1
	jmp epilogue

.globl _x86_test_ror
_x86_test_ror:
	xor		rax, rax
	add		rax, 1
	mov		rax, rdx
	ror		rax, cl
	jmp		epilogue

.globl _x86_test_sar1
_x86_test_sar1:
	add		rcx, 1
	mov		rax, rdx
	sar		rax, 1
	jmp epilogue

.globl _x86_test_sar
_x86_test_sar:
	xor		rax, rax
	add		rax, 1
	mov		rax, rdx
	sar		rax, cl
	jmp		epilogue

.globl _x86_test_seta
_x86_test_seta:
	xor		rax, rax
	cmp		rdx, rcx
	seta	al
	jmp epilogue

.globl _x86_test_setae
_x86_test_setae:
	xor		rax, rax
	cmp		rdx, rcx
	setae	al
	jmp epilogue

.globl _x86_test_setb
_x86_test_setb:
	xor		rax, rax
	cmp		rdx, rcx
	setb	al
	jmp epilogue

.globl _x86_test_setbe
_x86_test_setbe:
	xor		rax, rax
	cmp		rdx, rcx
	setbe	al
	jmp epilogue

.globl _x86_test_sete
_x86_test_sete:
	xor		rax, rax
	cmp		rdx, rcx
	sete	al
	jmp epilogue

.globl _x86_test_setg
_x86_test_setg:
	xor		rax, rax
	cmp		rdx, rcx
	setg	al
	jmp epilogue

.globl _x86_test_setge
_x86_test_setge:
	xor		rax, rax
	cmp		rdx, rcx
	setge	al
	jmp epilogue

.globl _x86_test_setl
_x86_test_setl:
	xor		rax, rax
	cmp		rdx, rcx
	setl	al
	jmp epilogue

.globl _x86_test_setle
_x86_test_setle:
	xor		rax, rax
	cmp		rdx, rcx
	setle	al
	jmp epilogue

.globl _x86_test_setne
_x86_test_setne:
	xor		rax, rax
	cmp		rdx, rcx
	setne	al
	jmp epilogue

.globl _x86_test_setno
_x86_test_setno:
	xor		rax, rax
	cmp		rdx, rcx
	setno	al
	jmp epilogue

.globl _x86_test_setnp
_x86_test_setnp:
	xor		rax, rax
	cmp		rdx, rcx
	setnp	al
	jmp epilogue

.globl _x86_test_setns
_x86_test_setns:
	xor		rax, rax
	cmp		rdx, rcx
	setns	al
	jmp epilogue

.globl _x86_test_seto
_x86_test_seto:
	xor		rax, rax
	cmp		rdx, rcx
	seto	al
	jmp epilogue

.globl _x86_test_setp
_x86_test_setp:
	xor		rax, rax
	cmp		rdx, rcx
	setp	al
	jmp epilogue

.globl _x86_test_sets
_x86_test_sets:
	xor		rax, rax
	cmp		rdx, rcx
	sets	al
	jmp epilogue

.globl _x86_test_shl1
_x86_test_shl1:
	add		rcx, 1
	mov		rax, rdx
	shl		rax, 1
	jmp epilogue

.globl _x86_test_shl
_x86_test_shl:
	xor		rax, rax
	add		rax, 1
	mov		rax, rdx
	shl		rax, cl
	jmp		epilogue

.globl _x86_test_shr1
_x86_test_shr1:
	add		rcx, 1
	mov		rax, rdx
	shr		rax, 1
	jmp epilogue

.globl _x86_test_shr
_x86_test_shr:
	xor		rax, rax
	add		rax, 1
	mov		rax, rdx
	shr		rax, cl
	jmp		epilogue

.globl _x86_test_stc
_x86_test_stc:
	xor		rax, rax
	add		rax, 1
	stc
	jmp		epilogue

.globl _x86_test_sub32
_x86_test_sub32:
	mov		eax, edx
	sub		eax, ecx
	jmp		epilogue

.globl _x86_test_sub64
_x86_test_sub64:
	mov		rax, rdx
	sub		rax, rcx
	jmp		epilogue

.globl _x86_test_test
_x86_test_test:
	xor		rax, rax
	test	rdx, rcx
	jmp		epilogue

.globl _x86_test_xor
_x86_test_xor:
	mov		rax, rdx
	xor		rax, rcx
	jmp		epilogue
