[bits 64]

extern interrupt_handler  ; Changed name from exception_handler to be generic
global load_idt
global isr_stub_table

section .text

load_idt:
    lidt [rdi] ; loads the 10-byte struct (Limit + Base) from the address in rdi into the idtr register.
    ret

; Common handler code
isr_common:
    ; 1. Save all registers
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rbp
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rax

    ; 2. Call C handler (Pass stack pointer as arg)
    mov rdi, rsp
    call interrupt_handler

    ; 3. Restore registers
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rbp
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15

    ; 4. Clean up error code and ISR number
    add rsp, 16 ; skips the Interrupt Number and Error Code pushed in the stub
    iretq ; pops RIP, CS, RFLAGS, RSP, and SS atomically, returning the CPU to exactly where it was before the interrupt

; Macros to generate ISR stubs
%macro ISR_NOERR 1
    global isr%1
    isr%1:
        push qword 0      ; Push dummy error code
        push qword %1     ; Push interrupt number
        jmp isr_common
%endmacro

%macro ISR_ERR 1
    global isr%1
    isr%1:
        push qword %1     ; Push interrupt number
        jmp isr_common
%endmacro

; --- EXCEPTION HANDLERS (0-31) ---
ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERR   8
ISR_NOERR 9
ISR_ERR   10
ISR_ERR   11
ISR_ERR   12
ISR_ERR   13
ISR_ERR   14
ISR_NOERR 15
ISR_NOERR 16
ISR_ERR   17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_NOERR 21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_NOERR 29
ISR_ERR   30
ISR_NOERR 31

; --- IRQ HANDLERS (32-47) ---
; These correspond to hardware interrupts (Timer, Keyboard, E1000, etc.)
ISR_NOERR 32
ISR_NOERR 33
ISR_NOERR 34
ISR_NOERR 35
ISR_NOERR 36
ISR_NOERR 37
ISR_NOERR 38
ISR_NOERR 39
ISR_NOERR 40
ISR_NOERR 41
ISR_NOERR 42
ISR_NOERR 43
ISR_NOERR 44
ISR_NOERR 45
ISR_NOERR 46
ISR_NOERR 47

section .data
global isr_stub_table
isr_stub_table:
    %assign i 0
    %rep 48          ; INCREASED from 32 to 48
        dq isr%+i
        %assign i i+1
    %endrep

section .note.GNU-stack noalloc noexec nowrite progbits