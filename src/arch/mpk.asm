[bits 64]

global mpk_enable
global mpk_set_pkru
global mpk_trampoline_0
global mpk_trampoline_1
global mpk_trampoline_2
global mpk_trampoline_3

section .text

; ---------------------------------------------------
; void mpk_enable()
;
; Sets CR4 bit 22 (PKE — Protection Key Enable).
; Must be called once before any WRPKRU/RDPKRU.
;
; Intel SDM Vol. 3A §2.5 — CR4.PKE (bit 22)
; ---------------------------------------------------
mpk_enable:
    mov rax, cr4
    bts rax, 22         ; Bit Test and Set bit 22 (PKE)
    mov cr4, rax
    ret


; ---------------------------------------------------
; void mpk_set_pkru(uint32_t pkru_val)
;
; Writes pkru_val directly to the PKRU register.
; Call this immediately after mpk_enable() to set
; the default restriction state for the kernel.
;
; Typical use:
;   mpk_set_pkru(0x0000000C);   // Key 1 disabled (AD+WD bits set)
;
; WRPKRU instruction (Intel SDM Vol. 2B):
;   Input:  EAX = new PKRU value
;           ECX = 0 (must be zero; non-zero raises #GP)
;           EDX = 0 (must be zero; non-zero raises #GP)
;   Output: PKRU ← EAX
;
; Arg: edi = pkru_val (System V ABI)
; ---------------------------------------------------
mpk_set_pkru:
    mov eax, edi        ; EAX = requested PKRU value
    xor ecx, ecx        ; ECX must be 0
    xor edx, edx        ; EDX must be 0
    wrpkru
    ret


; ===================================================================
; MPK TRAMPOLINE — generic pattern
;
; Problem being solved:
;   Normal kernel execution runs with PKRU = 0x0000000C.
;   Bits [3:2] = 0b11 mean Key 1 has both Access Disable (AD) and
;   Write Disable (WD) set — the CPU will fault on any read or write
;   to a Key-1 page (the e1000 driver's DMA rings and registers).
;
;   To call a driver function, we must:
;     1. Set PKRU = 0x00000000 (unlock Key 1 for the duration)
;     2. Call the driver function
;     3. Restore PKRU = 0x0000000C (re-lock Key 1)
;
;   save all arguments to callee-saved registers (R12–R15)
;   BEFORE touching ECX/EDX/EAX for WRPKRU.
;
; PKRU encoding for Key 1:
;   PKRU bit layout: ...[WD1][AD1][WD0][AD0]
;   Key 0 = bits [1:0]; Key 1 = bits [3:2]
;   0x0C = 0b00001100 → Key 1 AD=1, WD=1 (inaccessible to kernel)
;                      → Key 0 AD=0, WD=0 (accessible to kernel)
;
; System V AMD64 ABI register conventions:
;   Arguments  : RDI, RSI, RDX, RCX, R8, R9
;   Return     : RAX
;   Callee-saved: RBX, RBP, R12, R13, R14, R15
; ===================================================================


; ---------------------------------------------------
; int mpk_trampoline_0(void *func)
;
; Calls func() with no arguments through the MPK gate.
; Returns whatever func returns in RAX.
;
; Entry: RDI = func
; ---------------------------------------------------
mpk_trampoline_0:
    push rbp
    mov  rbp, rsp
    push r12

    mov  r12, rdi           ; r12 = func pointer

    ; ── 1. Unlock Key 1 ────────────────────────────
    xor  ecx, ecx           ; ECX = 0  (WRPKRU requirement)
    xor  edx, edx           ; EDX = 0  (WRPKRU requirement)
    xor  eax, eax           ; EAX = 0x00000000 → all keys accessible
    wrpkru

    ; ── 2. Call driver function ─────────────────────
    call r12                ; no arguments to set up

    ; ── 3. Save return value ────────────────────────
    push rax

    ; ── 4. Re-lock Key 1 ────────────────────────────
    xor  ecx, ecx
    xor  edx, edx
    mov  eax, 0x0C          ; Key 1: AD=1, WD=1
    wrpkru

    pop  rax                ; restore return value
    pop  r12
    pop  rbp
    ret


; ---------------------------------------------------
; int mpk_trampoline_1(void *func, uint64_t a0)
;
; Entry: RDI = func, RSI = a0
; ---------------------------------------------------
mpk_trampoline_1:
    push rbp
    mov  rbp, rsp
    push r12
    push r13

    mov  r12, rdi           ; r12 = func
    mov  r13, rsi           ; r13 = a0  (saved BEFORE WRPKRU clobbers regs)

    ; ── 1. Unlock Key 1 ────────────────────────────
    xor  ecx, ecx
    xor  edx, edx
    xor  eax, eax
    wrpkru

    ; ── 2. Restore argument, call ───────────────────
    mov  rdi, r13           ; arg0
    call r12

    ; ── 3/4. Save retval, re-lock ───────────────────
    push rax
    xor  ecx, ecx
    xor  edx, edx
    mov  eax, 0x0C
    wrpkru
    pop  rax

    pop  r13
    pop  r12
    pop  rbp
    ret


; ---------------------------------------------------
; int mpk_trampoline_2(void *func, uint64_t a0, uint64_t a1)
;
; Entry: RDI = func, RSI = a0, RDX = a1
;
; Example callers:
;   e1000_init(uint64_t mmio_base, uint8_t *mac_out)
;   e1000_read_reg(uint64_t base, uint32_t offset)
; ---------------------------------------------------
mpk_trampoline_2:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14

    mov  r12, rdi           ; r12 = func
    mov  r13, rsi           ; r13 = a0
    mov  r14, rdx           ; r14 = a1   (rdx MUST be saved; WRPKRU clobbers it)

    ; ── 1. Unlock Key 1 ────────────────────────────
    xor  ecx, ecx           ; clears rcx (was not an arg here, but be explicit)
    xor  edx, edx           ; clears rdx — r14 already holds a1
    xor  eax, eax
    wrpkru

    ; ── 2. Restore args, call ───────────────────────
    mov  rdi, r13           ; arg0
    mov  rsi, r14           ; arg1
    call r12

    ; ── 3/4. Save retval, re-lock ───────────────────
    push rax
    xor  ecx, ecx
    xor  edx, edx
    mov  eax, 0x0C
    wrpkru
    pop  rax

    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret


; ---------------------------------------------------
; int mpk_trampoline_3(void *func,
;                      uint64_t a0, uint64_t a1, uint64_t a2)
;
; Entry: RDI = func, RSI = a0, RDX = a1, RCX = a2
;
; Example callers:
;   e1000_send_raw(uint64_t mmio, void *data, uint16_t len)
;   e1000_poll_receive(uint64_t mmio, void *buf, uint16_t max)
;   e1000_write_reg(uint64_t base, uint32_t off, uint32_t val)
; ---------------------------------------------------
mpk_trampoline_3:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    push r15

    mov  r12, rdi           ; r12 = func
    mov  r13, rsi           ; r13 = a0
    mov  r14, rdx           ; r14 = a1
    mov  r15, rcx           ; r15 = a2

    ; ── 1. Unlock Key 1 ────────────────────────────
    xor  ecx, ecx           ; WRPKRU requires ECX=0
    xor  edx, edx           ; WRPKRU requires EDX=0
    xor  eax, eax           ; PKRU = 0x00000000 (all keys accessible)
    wrpkru

    ; ── 2. Restore args, call ───────────────────────
    mov  rdi, r13           ; arg0
    mov  rsi, r14           ; arg1
    mov  rdx, r15           ; arg2
    call r12

    ; ── 3/4. Save retval, re-lock ───────────────────
    push rax
    xor  ecx, ecx
    xor  edx, edx
    mov  eax, 0x0C          ; PKRU = 0x0000000C → Key 1: AD=1, WD=1 (locked)
    wrpkru
    pop  rax

    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret


section .note.GNU-stack noalloc noexec nowrite progbits