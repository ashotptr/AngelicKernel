[bits 64]

global mpk_enable
global mpk_set_pkru
global mpk_trampoline_0
global mpk_trampoline_1
global mpk_trampoline_2
global mpk_trampoline_3
global mpk_trampoline_4

section .text

mpk_enable:
    mov rax, cr4
    bts rax, 22
    mov cr4, rax
    ret

mpk_set_pkru:
    mov eax, edi
    xor ecx, ecx
    xor edx, edx
    wrpkru
    ret

mpk_trampoline_0:
    push rbp
    mov rbp, rsp
    push r12

    mov r12, rdi

    xor ecx, ecx
    xor edx, edx
    xor eax, eax
    wrpkru

    call r12

    push rax

    xor ecx, ecx
    xor edx, edx
    mov eax, 0x0C
    wrpkru

    pop rax
    pop r12
    pop rbp
    ret

mpk_trampoline_1:
    push rbp
    mov rbp, rsp
    push r12
    push r13

    mov r12, rdi
    mov r13, rsi
    
    xor ecx, ecx
    xor edx, edx
    xor eax, eax
    wrpkru

    mov rdi, r13
    call r12

    push rax
    xor ecx, ecx
    xor edx, edx
    mov eax, 0x0C
    wrpkru
    pop rax

    pop r13
    pop r12
    pop rbp
    ret

mpk_trampoline_2:
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14

    mov r12, rdi
    mov r13, rsi
    mov r14, rdx

    xor ecx, ecx
    xor edx, edx
    xor eax, eax
    wrpkru

    mov rdi, r13
    mov rsi, r14
    call r12

    push rax
    xor ecx, ecx
    xor edx, edx
    mov eax, 0x0C
    wrpkru
    pop rax

    pop r14
    pop r13
    pop r12
    pop rbp
    ret

mpk_trampoline_3:
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx

    xor ecx, ecx
    xor edx, edx
    xor eax, eax
    wrpkru

    mov rdi, r13
    mov rsi, r14
    mov rdx, r15
    call r12

    push rax
    xor ecx, ecx
    xor edx, edx
    mov eax, 0x0C
    wrpkru
    pop rax

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    ret

mpk_trampoline_4:
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14
    push r15
 
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx

    push r8
 
    xor ecx, ecx
    xor edx, edx
    xor eax, eax
    wrpkru
 
    mov rdi, r13
    mov rsi, r14
    mov rdx, r15
    pop rcx
    call r12
 
    push rax
    xor ecx, ecx
    xor edx, edx
    mov eax, 0x0C
    wrpkru
    pop rax
 
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits