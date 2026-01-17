#include "mm/vmm.h"
#include "mm/pmm.h"
// OR just add these lines near the top if you don't have a header yet:
void serial_print(char* s);
void serial_print_hex(uint64_t n);
// Helper to access PMM (from your previous step)
// We assume pmm_alloc_page returns a zeroed 4KB page.

// Masks to extract indices from a virtual address
#define PML4_INDEX(x) (((x) >> 39) & 0x1FF)
#define PDP_INDEX(x)  (((x) >> 30) & 0x1FF)
#define PD_INDEX(x)   (((x) >> 21) & 0x1FF)
#define PT_INDEX(x)   (((x) >> 12) & 0x1FF)

// The Root Page Table (Physical Address)
uint64_t* kernel_pml4 = 0;

void vmm_map_page(uint64_t virt, uint64_t phys, uint64_t flags) {
    uint64_t* pml4 = kernel_pml4;
    
    // 1. Get PDP
    uint64_t idx = PML4_INDEX(virt);
    if (!(pml4[idx] & PTE_PRESENT)) {
        pml4[idx] = (uint64_t)pmm_alloc_page() | PTE_PRESENT | PTE_WRITE;
    }
    uint64_t* pdp = (uint64_t*)(pml4[idx] & ~0xFFF); // Clear flags to get address

    // 2. Get PD
    idx = PDP_INDEX(virt);
    if (!(pdp[idx] & PTE_PRESENT)) {
        pdp[idx] = (uint64_t)pmm_alloc_page() | PTE_PRESENT | PTE_WRITE;
    }
    uint64_t* pd = (uint64_t*)(pdp[idx] & ~0xFFF);

    // 3. Get PT
    idx = PD_INDEX(virt);
    if (!(pd[idx] & PTE_PRESENT)) {
        pd[idx] = (uint64_t)pmm_alloc_page() | PTE_PRESENT | PTE_WRITE;
    }
    uint64_t* pt = (uint64_t*)(pd[idx] & ~0xFFF);

    // 4. Set the Page Table Entry (The Actual Mapping)
    pt[PT_INDEX(virt)] = phys | flags;
}

// Assembly helper to load CR3 register
extern void load_cr3(uint64_t pml4_addr);

void vmm_init() {
    serial_print("[VMM] Creating new Page Tables...\n");

    // 1. Allocate the Root Table (PML4)
    kernel_pml4 = (uint64_t*)pmm_alloc_page();

    // 2. Identity Map the first 4GB of RAM
    // This covers the Kernel code, the Stack, Video Memory, and MMIO devices.
    // We map it as Read/Write (PTE_WRITE) + Present (PTE_PRESENT).
    // Note: This loop maps 1 MILLION pages. It might take a split second.
    uint64_t limit = 0x100000000; // 4GB
    for (uint64_t addr = 0; addr < limit; addr += PAGE_SIZE) {
        vmm_map_page(addr, addr, PTE_PRESENT | PTE_WRITE);
    }

    serial_print("[VMM] Tables built. Switching CR3...\n");

    // 3. Load CR3 (Switch to our tables)
    // We need inline assembly for this.
    __asm__ volatile("mov %0, %%cr3" : : "r"(kernel_pml4));

    serial_print("[VMM] CR3 Switched. We now own the memory!\n");
}

extern uint64_t __secure_driver_data_start;
extern uint64_t __secure_driver_data_end;

// Helper to set PKEY bits on an existing page
void vmm_set_pkey(uint64_t virt, int pkey) {
    uint64_t* pml4 = kernel_pml4;
    uint64_t idx = PML4_INDEX(virt);
    uint64_t* pdp = (uint64_t*)(pml4[idx] & ~0xFFF);
    
    idx = PDP_INDEX(virt);
    uint64_t* pd = (uint64_t*)(pdp[idx] & ~0xFFF);
    
    idx = PD_INDEX(virt);
    uint64_t* pt = (uint64_t*)(pd[idx] & ~0xFFF);
    
    // Set bits 59-62
    pt[PT_INDEX(virt)] &= ~(0xFULL << 59); // Clear old key
    pt[PT_INDEX(virt)] |= PTE_PKEY(pkey);  // Set new key
    
    // Invalidate TLB for this address
    __asm__ volatile("invlpg (%0)" :: "r" (virt) : "memory");
}

void vmm_protect_driver() {
    serial_print("[VMM] Locking down e1000 Driver...\n");
    
    uint64_t start = (uint64_t)&__secure_driver_data_start;
    uint64_t end   = (uint64_t)&__secure_driver_data_end;
    
    serial_print("      Target Range: 0x"); serial_print_hex(start);
    serial_print(" - 0x"); serial_print_hex(end); serial_print("\n");

    for (uint64_t addr = start; addr < end; addr += PAGE_SIZE) {
        vmm_set_pkey(addr, 1); // Key 1 = Secure Driver
    }
    
    serial_print("[VMM] Driver Locked. Key 1 required for access.\n");
}