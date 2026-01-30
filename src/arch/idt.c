#include <stdint.h>

// Matches the registers saved in assembly
typedef struct {
    // General Purpose Registers (Last pushed = First here)
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;

    // Interrupt info (Pushed by our macros)
    uint64_t int_no;
    uint64_t err_code;

    // Return Stack (Pushed by CPU)
    uint64_t rip, cs, rflags, rsp, ss;
} __attribute__((packed)) registers_t;

typedef struct {
    uint16_t isr_low;    // The lower 16 bits of the handler's memory address
    uint16_t kernel_cs;  // The Code Segment Selector (Where is the code?)
    uint8_t  ist;        // Interrupt Stack Table (Stack switching mechanism)
    uint8_t  attributes; // Type (Interrupt vs Trap), DPL (Permissions), Present bit
    uint16_t isr_mid;    // The middle 16 bits of the handler's address
    uint32_t isr_high;   // The upper 32 bits of the handler's address
    uint32_t reserved;   // Must be ZERO.
} __attribute__((packed)) idt_entry_t;

typedef struct {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) idtr_t;

__attribute__((aligned(0x10))) 
static idt_entry_t idt[256];
static idtr_t idtr;

extern uint32_t e1000_read_reg(uint64_t base, uint32_t offset);
extern uint64_t global_mmio_base; // You need to store mmio_base globally to use it here
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

#define PIC1 0x20 // IO base for master PIC
#define PIC2 0xA0 // IO base for slave PIC
#define PIC1_COMMAND PIC1
#define PIC1_DATA (PIC1 + 1)
#define PIC2_COMMAND PIC2
#define PIC2_DATA (PIC2 + 1)

void pic_remap(int offset1, int offset2) {
	unsigned char a1, a2;
	a1 = inb(PIC1_DATA); // save masks, read the current "Interrupt Mask Register" (IMR)
	a2 = inb(PIC2_DATA);

	outb(PIC1_COMMAND, 0x11); // ICW1: Initialization Command, starts the initialization sequence (in cascade mode)
	outb(PIC2_COMMAND, 0x11);

	outb(PIC1_DATA, offset1); // ICW2: Master PIC vector offset
	outb(PIC2_DATA, offset2); // ICW2: Slave PIC vector offset

	outb(PIC1_DATA, 4); // ICW3: tell Master PIC that there is a slave PIC at IRQ2 (0000 0100)
	outb(PIC2_DATA, 2); // ICW3: tell Slave PIC its cascade identity (0000 0010)

	outb(PIC1_DATA, 0x01); // ICW4: 8086 mode
	outb(PIC2_DATA, 0x01);

	outb(PIC1_DATA, a1); // restore saved masks.
	outb(PIC2_DATA, a2);
}

void pic_send_eoi(unsigned char irq) {
	if (irq >= 8) {
        outb(PIC2_COMMAND, 0x20); // The Value 0x20 is the specific command byte for "Non-Specific EOI."
    }

	outb(PIC1_COMMAND, 0x20);
}

void idt_set_gate(uint8_t vector, void* isr) {
    uint64_t addr = (uint64_t)isr;
    idt[vector].isr_low = addr & 0xFFFF;
    idt[vector].kernel_cs = 0x38; // tells the CPU which GDT segment the Interrupt Handler code lives in. 64-bit Kernel Code Segment is located at offset 0x38.
    idt[vector].ist = 0; // do not use the IST(Interrupt Stack Table), use the standard legacy stack switching mechanism.
    idt[vector].attributes = 0x8E; // value is 1000 1110, bit 7 (Present = 1), bits 6-5 (DPL = 00) only the Kernel (Ring 0) can access this, bit 4 (S = 0) Interrupt/Trap Gates, Bits 3-0 (Type = 1110): 64-bit Interrupt Gate
    idt[vector].isr_mid = (addr >> 16) & 0xFFFF;
    idt[vector].isr_high = (addr >> 32) & 0xFFFFFFFF;
    idt[vector].reserved = 0; // must be zero
}

void init_idt() {
    // 1. Remap PIC so hardware IRQs start at 32 instead of 0
    pic_remap(32, 40);

    // 2. Unmask all interrupts (for now) to ensure we get e1000
    outb(PIC1_DATA, 0x00);
    outb(PIC2_DATA, 0x00);

    // 3. Install stubs for Exceptions (0-31) and IRQs (32-47)
    for (int i = 0; i < 48; i++) {
        idt_set_gate(i, isr_stub_table[i]);
    }

    idtr.limit = sizeof(idt) - 1;
    idtr.base = (uint64_t)&idt;
    load_idt(&idtr);
    
    serial_print("[KERNEL] IDT Initialized (PIC Remapped).\n");
}

void interrupt_handler(registers_t* regs) {
    // Case 1: Hardware Interrupts (IRQs)
    if (regs->int_no >= 32 && regs->int_no < 48) {
        // serial_print("IRQ Received\n");
        
        // check pci interrupt (IRQ 10 or 11 for QEMU e1000), check e1000 status for IRQ > 32 to be safe for this phase
        if (global_mmio_base != 0) {
             uint32_t cause = e1000_read_reg(global_mmio_base, 0xC0); // 0xC0 = ICR (Interrupt Cause Register)

             if (cause & 0x80) { // Bit 7 = RXT0 (Timer Interrupt / Packet Received)
                 // A packet is waiting!
                 // Ideally, you set a flag here, but for now, we just clear it.
                 serial_print("[INT] Packet Arrived!\n");
             }
        }

        pic_send_eoi(regs->int_no - 32);

        return;
    }

    // Case 2: CPU Exceptions
    serial_print("\n!!! CPU EXCEPTION !!!\n");
    serial_print("INT Number: "); serial_print_hex(regs->int_no);
    serial_print("\nError Code: "); serial_print_hex(regs->err_code);
    serial_print("\nRIP: "); serial_print_hex(regs->rip);

    if (regs->int_no == 14) {
        uint64_t cr2;
        __asm__ volatile ("mov %%cr2, %0" : "=r"(cr2));
        serial_print("\nPAGE FAULT @ Address: ");
        serial_print_hex(cr2);
    } 

    serial_print("\nHalting system.\n");
    __asm__ volatile ("cli; hlt");
}