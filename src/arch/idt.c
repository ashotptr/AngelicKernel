#include <stdint.h>

volatile int packet_pending = 0;

typedef struct {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;

    uint64_t int_no;
    uint64_t err_code;

    uint64_t rip, cs, rflags, rsp, ss;
} __attribute__((packed)) registers_t;

typedef struct {
    uint16_t isr_low;
    uint16_t kernel_cs;
    uint8_t ist;
    uint8_t attributes;
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

static inline void outb(uint16_t port, uint8_t val) {
    __asm__ volatile ( "outb %0, %1" : : "a"(val), "Nd"(port) );
}
static inline uint8_t inb(uint16_t port) {
    uint8_t ret;
    __asm__ volatile ( "inb %1, %0" : "=a"(ret) : "Nd"(port) );
    return ret;
}

#define PIC1 0x20
#define PIC2 0xA0
#define PIC1_COMMAND PIC1
#define PIC1_DATA (PIC1 + 1)
#define PIC2_COMMAND PIC2
#define PIC2_DATA (PIC2 + 1)

void pic_remap(int offset1, int offset2) {
	unsigned char a1, a2;
	a1 = inb(PIC1_DATA);
	a2 = inb(PIC2_DATA);

	outb(PIC1_COMMAND, 0x11);
	outb(PIC2_COMMAND, 0x11);

	outb(PIC1_DATA, offset1);
	outb(PIC2_DATA, offset2);

	outb(PIC1_DATA, 4);
	outb(PIC2_DATA, 2);

	outb(PIC1_DATA, 0x01);
	outb(PIC2_DATA, 0x01);

	outb(PIC1_DATA, a1);
	outb(PIC2_DATA, a2);
}

void pic_send_eoi(unsigned char irq) {
	if (irq >= 8) {
        outb(PIC2_COMMAND, 0x20);
    }

	outb(PIC1_COMMAND, 0x20);
}

void idt_set_gate(uint8_t vector, void* isr) {
    uint64_t addr = (uint64_t)isr;
    idt[vector].isr_low = addr & 0xFFFF;
    idt[vector].kernel_cs = 0x38;
    idt[vector].ist = 0;
    idt[vector].attributes = 0x8E;
    idt[vector].isr_mid = (addr >> 16) & 0xFFFF;
    idt[vector].isr_high = (addr >> 32) & 0xFFFFFFFF;
    idt[vector].reserved = 0;
}

void init_idt() {
    pic_remap(32, 40);

    outb(PIC1_DATA, 0x00);
    outb(PIC2_DATA, 0x00);

    for (int i = 0; i < 48; i++) {
        idt_set_gate(i, isr_stub_table[i]);
    }

    idtr.limit = sizeof(idt) - 1;
    idtr.base = (uint64_t)&idt;

    load_idt(&idtr);
    
    serial_print("[kernel] idt initialized (pic remapped).\n");
}

void interrupt_handler(registers_t* regs) {
    if (regs->int_no == 14) {
        extern volatile int mpk_test_in_progress;
        extern volatile int mpk_test_fault_occurred;

        if (mpk_test_in_progress) {
            mpk_test_fault_occurred = 1;
            mpk_test_in_progress = 0;
            regs->rip += 2;

            return;
        }
    }
    
    if (regs->int_no >= 32 && regs->int_no < 48) {
        packet_pending = 1;

        pic_send_eoi(regs->int_no - 32);

        return;
    }
    
    serial_print("\ncpu exception\n");
    serial_print("int number: ");
    serial_print_hex(regs->int_no);
    serial_print("\nerror code: ");
    serial_print_hex(regs->err_code);
    serial_print("\nrip: ");
    serial_print_hex(regs->rip);

    if (regs->int_no == 14) {
        uint64_t cr2;
        
        __asm__ volatile ("mov %%cr2, %0" : "=r"(cr2));

        serial_print("\npage fault @ address: ");
        
        serial_print_hex(cr2);
    } 

    serial_print("\nhalting system\n");
    
    __asm__ volatile ("cli; hlt");
}