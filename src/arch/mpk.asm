[bits 64]

global mpk_enable
global mpk_trampoline_3  ; For functions with 3 arguments

section .text

; ---------------------------------------------------
; void mpk_enable()
; Sets CR4 bit 22 (Protection Key Enable)
; ---------------------------------------------------
mpk_enable:
    mov rax, cr4
    bts rax, 22        ; Bit Test and Set bit 22
    mov cr4, rax
    ret

; ---------------------------------------------------
; int mpk_trampoline_3(void* func, uint64_t arg1, uint64_t arg2, uint64_t arg3)
; 
; System V ABI:
; func -> rdi
; arg1 -> rsi
; arg2 -> rdx
; arg3 -> rcx
;
; Goal: Enable Key 1 -> Call func -> Disable Key 1
; ---------------------------------------------------
mpk_trampoline_3:
    push rbp
    mov rbp, rsp
    push rbx            ; Save callee-saved register
    push r12            ; We will use r12 to save the function pointer

    mov r12, rdi        ; Save function pointer

    ; 1. UNLOCK THE GATE (Enable access to Key 1)
    ; PKRU Register:
    ; Bit 0-1: Key 0 (Kernel) -> 00 (RW)
    ; Bit 2-3: Key 1 (Driver) -> 00 (RW)
    xor ecx, ecx        ; ECX = 0 (PKRU register index)
    xor edx, edx        ; EDX = 0 (Upper 32 bits must be 0)
    xor eax, eax        ; EAX = 0 (Allow everything)
    wrpkru

    ; 2. CALL THE DRIVER
    ; Restore arguments to correct registers for the target function
    mov rdi, rsi        ; arg1
    mov rsi, rdx        ; arg2
    mov rdx, rcx        ; arg3
    call r12            ; Call the driver function

    ; Save return value
    push rax

    ; 3. LOCK THE GATE (Disable access to Key 1)
    ; Bit 2 (Access Disable) = 1, Bit 3 (Write Disable) = 1 for Key 1
    ; Key 1 is bits [3:2] -> Binary 1100 -> Hex 0xC
    xor ecx, ecx
    xor edx, edx
    mov eax, 0x0C       ; Disable Key 1
    wrpkru

    ; Restore return value and registers
    pop rax
    pop r12
    pop rbx
    pop rbp
    ret

; Mark the stack as non-executable (silences linker warning)
section .note.GNU-stack noalloc noexec nowrite progbits

; WARNING: This trampoline uses System V ABI. 
; DO NOT use this to call UEFI functions (gBS, gST, etc). 
; Only use this for internal kernel functions.