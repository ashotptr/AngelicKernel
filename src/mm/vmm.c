#include "mm/vmm.h"
#include "mm/pmm.h"

void serial_print(const char* s);
void serial_print_hex(uint64_t n);

#define PML4_INDEX(x) (((x) >> 39) & 0x1FF)
#define PDP_INDEX(x) (((x) >> 30) & 0x1FF)
#define PD_INDEX(x) (((x) >> 21) & 0x1FF)
#define PT_INDEX(x) (((x) >> 12) & 0x1FF)

uint64_t* kernel_pml4 = 0;

uint64_t virt_to_phys(void* addr) {
    return (uint64_t)addr;
}

void vmm_map_page(uint64_t virt, uint64_t phys, uint64_t flags) {
    uint64_t* pml4 = kernel_pml4;

    uint64_t idx = PML4_INDEX(virt);

    if (!(pml4[idx] & PTE_PRESENT)) {
        pml4[idx] = (uint64_t)pmm_alloc_page() | PTE_PRESENT | PTE_WRITE | PTE_USER;
    }

    uint64_t* pdp = (uint64_t*)(pml4[idx] & ~0xFFFull);

    idx = PDP_INDEX(virt);

    if (!(pdp[idx] & PTE_PRESENT)) {
        pdp[idx] = (uint64_t)pmm_alloc_page() | PTE_PRESENT | PTE_WRITE | PTE_USER;
    }

    uint64_t* pd = (uint64_t*)(pdp[idx] & ~0xFFFull);

    idx = PD_INDEX(virt);

    if (!(pd[idx] & PTE_PRESENT)) {
        pd[idx] = (uint64_t)pmm_alloc_page() | PTE_PRESENT | PTE_WRITE | PTE_USER;
    }

    uint64_t* pt = (uint64_t*)(pd[idx] & ~0xFFFull);

    pt[PT_INDEX(virt)] = phys | flags;
}

void vmm_init() {
    serial_print("[vmm] creating new page rables\n");

    kernel_pml4 = (uint64_t*)pmm_alloc_page();

    uint64_t limit = 0x100000000ULL;

    for (uint64_t addr = 0; addr < limit; addr += PAGE_SIZE) {
        vmm_map_page(addr, addr, PTE_PRESENT | PTE_WRITE | PTE_USER);
    }

    serial_print("[vmm] tables built\n");

    __asm__ volatile("mov %0, %%cr3" : : "r"(kernel_pml4));

    serial_print("[vmm] cr3 switched\n");
}

extern uint64_t __secure_driver_code_start;
extern uint64_t __secure_driver_code_end;
extern uint64_t __secure_driver_data_start;
extern uint64_t __secure_driver_data_end;

void vmm_set_pkey(uint64_t virt, int pkey) {
    uint64_t* pml4 = kernel_pml4;
    uint64_t* pdp = (uint64_t*)(pml4[PML4_INDEX(virt)] & ~0xFFFull);
    uint64_t* pd = (uint64_t*)(pdp[PDP_INDEX(virt)] & ~0xFFFull);
    uint64_t* pt = (uint64_t*)(pd[PD_INDEX(virt)] & ~0xFFFull);

    uint64_t* pte = &pt[PT_INDEX(virt)];

    *pte &= ~(0xFULL << 59);
    *pte |= PTE_PKEY(pkey);
    *pte |= PTE_USER;

    __asm__ volatile("invlpg (%0)" :: "r" (virt) : "memory");
}

void vmm_protect_driver(void) {
    serial_print("[vmm] locking e1000 driver\n");

    uint64_t code_start = (uint64_t)&__secure_driver_code_start;
    uint64_t code_end = (uint64_t)&__secure_driver_code_end;

    serial_print("[vmm] code range: 0x");
    serial_print_hex(code_start);
    serial_print(" - 0x");
    serial_print_hex(code_end);
    serial_print("\n");

    for (uint64_t addr = code_start; addr < code_end; addr += PAGE_SIZE) {
        vmm_set_pkey(addr, 1);
    }

    uint64_t data_start = (uint64_t)&__secure_driver_data_start;
    uint64_t data_end = (uint64_t)&__secure_driver_data_end;

    serial_print("[vmm] data range: 0x");
    serial_print_hex(data_start);
    serial_print(" - 0x");
    serial_print_hex(data_end);
    serial_print("\n");

    for (uint64_t addr = data_start; addr < data_end; addr += PAGE_SIZE){
        vmm_set_pkey(addr, 1);
    }

    serial_print("[vmm] driver locked\n");
}