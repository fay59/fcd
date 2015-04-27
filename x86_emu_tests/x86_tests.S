.section __TEXT,__text,regular,pure_instructions
.macosx_version_min 10, 10
.align	4, 0x90

_exit_func:
    pushf
    pop		cx
    mov		qword ptr [rdi], rax
    mov		word ptr [rsi], cx
    ret

.globl _x86_test_adc32
_x86_test_adc32:
    xor		rax, rax
    add		rax, 1

	mov		eax, edx
	stc
	adc		eax, ecx
	jmp		_exit_func

.globl _x86_test_adc64
_x86_test_adc64:
    xor		rax, rax
    add		rax, 1

	mov		rax, rdx
	stc
	adc		rax, rcx
	jmp		_exit_func

.globl _x86_test_and32
_x86_test_and32:
    xor		rax, rax
    add		rax, 1

	mov		eax, edx
	and		eax, ecx
	jmp		_exit_func

.globl _x86_test_and64
_x86_test_and64:
    xor		rax, rax
    add		rax, 1

	mov		rax, rdx
	and		rax, rcx
	jmp		_exit_func

.globl _x86_test_call
_x86_test_call:
	push	rbp
	call	test_call
	pop		rbp
	jmp		_exit_func
test_call:
	mov		rax, qword ptr [rsp]
	ret

.globl _x86_test_mov
_x86_test_mov:
    mov		rax, rdx
    jmp		_exit_func
