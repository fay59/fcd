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

epilogue:
    pushf
    pop		cx
    mov		qword ptr [rdi], rax
    mov		word ptr [rsi], cx
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
	jrcxz	test_jcx_epilogue
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
