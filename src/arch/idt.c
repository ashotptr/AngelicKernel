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

extern uint32_t e1000_read_reg(uint64_t base, uint32_t offset);
extern uint64_t global_mmio_base; // You need to store mmio_base globally to use it here
extern void* isr_stub_table[];
extern void load_idt(void* idtr_ptr);
extern void serial_print(const char* str);
extern void serial_print_hex(uint64_t n);

// --- IO PORT HELPERS ---
static inline void outb(uint16_t port, uint8_t val) {
    __asm__ volatile ( "outb %0, %1" : : "a"(val), "Nd"(port) );
}
static inline uint8_t inb(uint16_t port) {
    uint8_t ret;
    __asm__ volatile ( "inb %1, %0" : "=a"(ret) : "Nd"(port) );
    return ret;
}

// --- PIC REMAPPING ---
#define PIC1		0x20		/* IO base for master PIC */
#define PIC2		0xA0		/* IO base for slave PIC */
#define PIC1_COMMAND	PIC1
#define PIC1_DATA	(PIC1+1)
#define PIC2_COMMAND	PIC2
#define PIC2_DATA	(PIC2+1)

void pic_remap(int offset1, int offset2) {
	unsigned char a1, a2;
	a1 = inb(PIC1_DATA);                        // save masks
	a2 = inb(PIC2_DATA);
	outb(PIC1_COMMAND, 0x11);  // starts the initialization sequence (in cascade mode)
	outb(PIC2_COMMAND, 0x11);
	outb(PIC1_DATA, offset1);                 // ICW2: Master PIC vector offset
	outb(PIC2_DATA, offset2);                 // ICW2: Slave PIC vector offset
	outb(PIC1_DATA, 4);                       // ICW3: tell Master PIC that there is a slave PIC at IRQ2 (0000 0100)
	outb(PIC2_DATA, 2);                       // ICW3: tell Slave PIC its cascade identity (0000 0010)
	outb(PIC1_DATA, 0x01);                    // ICW4: 8086 mode
	outb(PIC2_DATA, 0x01);
	outb(PIC1_DATA, a1);   // restore saved masks.
	outb(PIC2_DATA, a2);
}

void pic_send_eoi(unsigned char irq) {
	if(irq >= 8) outb(PIC2_COMMAND, 0x20);
	outb(PIC1_COMMAND, 0x20);
}

// --- IDT SETUP ---
void idt_set_gate(uint8_t vector, void* isr) {
    uint64_t addr = (uint64_t)isr;
    idt[vector].isr_low = addr & 0xFFFF;
    idt[vector].kernel_cs = 0x38; // Check your specific UEFI CS. Typically 0x38 or 0x08.
    idt[vector].ist = 0;
    idt[vector].attributes = 0x8E; // Present, Ring 0, Interrupt Gate
    idt[vector].isr_mid = (addr >> 16) & 0xFFFF;
    idt[vector].isr_high = (addr >> 32) & 0xFFFFFFFF;
    idt[vector].reserved = 0;
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

// --- MAIN HANDLER ---
// Renamed from exception_handler to reflect it handles everything
void interrupt_handler(registers_t* regs) {
    // Case 1: Hardware Interrupts (IRQs)
    if (regs->int_no >= 32 && regs->int_no < 48) {
        // serial_print("IRQ Received\n"); // Comment out to avoid spamming serial
        
        // CHECK PCI INTERRUPT (Usually IRQ 10 or 11 for QEMU e1000)
        // We blindly check e1000 status for ANY IRQ > 32 just to be safe for this phase
        if (global_mmio_base != 0) {
             uint32_t cause = e1000_read_reg(global_mmio_base, 0xC0); // 0xC0 = ICR
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