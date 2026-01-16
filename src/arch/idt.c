#include <stdint.h>

// Matches the registers saved in assembly
typedef struct {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t int_no;
    uint64_t err_code;
    uint64_t rip, cs, rflags, rsp, ss;
} __attribute__((packed)) registers_t;

typedef struct {
    uint16_t isr_low;
    uint16_t kernel_cs;
    uint8_t  ist;
    uint8_t  attributes;
    uint16_t isr_mid;
    uint32_t isr_high;
    uint32_t reserved;
} __attribute__((packed)) idt_entry_t;

typedef struct {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) idtr_t;

__attribute__((aligned(0x10))) 
static idt_entry_t idt[256];
static idtr_t idtr;

extern void* isr_stub_table[];
extern void load_idt(void* idtr_ptr);
extern void serial_print(const char* str);
extern void serial_print_hex(uint64_t n);

void idt_set_gate(uint8_t vector, void* isr) {
    uint64_t addr = (uint64_t)isr;
    idt[vector].isr_low = addr & 0xFFFF;
    idt[vector].kernel_cs = 0x38; // Default UEFI Code Segment (might vary, but usually 0x38)
    idt[vector].ist = 0;
    idt[vector].attributes = 0x8E; // Present, Ring 0, Interrupt Gate
    idt[vector].isr_mid = (addr >> 16) & 0xFFFF;
    idt[vector].isr_high = (addr >> 32) & 0xFFFFFFFF;
    idt[vector].reserved = 0;
}

void init_idt() {
    for (int i = 0; i < 32; i++) {
        idt_set_gate(i, isr_stub_table[i]);
    }
    idtr.limit = sizeof(idt) - 1;
    idtr.base = (uint64_t)&idt;
    load_idt(&idtr);
    serial_print("[KERNEL] IDT Initialized.\n");
}

void exception_handler(registers_t* regs) {
    serial_print("\n!!! CPU EXCEPTION !!!\n");
    serial_print("INT Number: "); serial_print_hex(regs->int_no);
    serial_print("\nError Code: "); serial_print_hex(regs->err_code);
    serial_print("\nRIP: "); serial_print_hex(regs->rip);

    if (regs->int_no == 14) {
        uint64_t cr2;
        __asm__ volatile ("mov %%cr2, %0" : "=r"(cr2));
        serial_print("\nPAGE FAULT @ Address: ");
        serial_print_hex(cr2);
    } else if (regs->int_no == 13) {
        serial_print("\nGENERAL PROTECTION FAULT");
    }

    serial_print("\nHalting system.\n");
    __asm__ volatile ("cli; hlt");
}