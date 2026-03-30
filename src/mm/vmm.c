#include "mm/vmm.h"
#include "mm/pmm.h"

void serial_print(const char* s);
void serial_print_hex(uint64_t n);

#define PML4_INDEX(x) (((x) >> 39) & 0x1FF)
#define PDP_INDEX(x)  (((x) >> 30) & 0x1FF)
#define PD_INDEX(x)   (((x) >> 21) & 0x1FF)
#define PT_INDEX(x)   (((x) >> 12) & 0x1FF)

uint64_t* kernel_pml4 = 0;

uint64_t virt_to_phys(void* addr) {
    return (uint64_t)addr; /* 1:1 identity mapping */
}

void vmm_map_page(uint64_t virt, uint64_t phys, uint64_t flags) {
    uint64_t* pml4 = kernel_pml4;

    uint64_t idx = PML4_INDEX(virt);

    if (!(pml4[idx] & PTE_PRESENT)) {
        // Add PTE_USER so this subtree can contain user-mode pages
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
    serial_print("[VMM] Creating new Page Tables...\n");

    kernel_pml4 = (uint64_t*)pmm_alloc_page();

    /* Identity-map the first 4 GB (covers MMIO, DMA buffers, kernel) */
    uint64_t limit = 0x100000000ULL;

    for (uint64_t addr = 0; addr < limit; addr += PAGE_SIZE) {
        vmm_map_page(addr, addr, PTE_PRESENT | PTE_WRITE | PTE_USER);
    }

    serial_print("[VMM] Tables built. Switching CR3...\n");

    __asm__ volatile("mov %0, %%cr3" : : "r"(kernel_pml4));

    serial_print("[VMM] CR3 switched. Kernel now owns memory.\n");
}

/* -----------------------------------------------------------------------
 * External linker-script symbols marking the secure driver sections.
 * Defined by linker.ld; declared here for use in vmm_protect_driver().
 * ----------------------------------------------------------------------- */
extern uint64_t __secure_driver_code_start;
extern uint64_t __secure_driver_code_end;
extern uint64_t __secure_driver_data_start;
extern uint64_t __secure_driver_data_end;

/* -----------------------------------------------------------------------
 * vmm_set_pkey — apply an MPK protection key to a single 4 KB page.
 *
 * Walks the live page table to the PT entry for `virt`, clears the
 * current key in bits [62:59], sets the new key, and flushes the TLB
 * entry with INVLPG.
 *
 * Intel SDM Vol. 3A §4.6.2 — Protection Keys:
 *   Bits 62:59 of a PTE carry the protection key (0–15).
 *   The PKRU register controls which keys are readable/writable.
 * ----------------------------------------------------------------------- */
void vmm_set_pkey(uint64_t virt, int pkey) {
    uint64_t* pml4 = kernel_pml4;
    uint64_t* pdp = (uint64_t*)(pml4[PML4_INDEX(virt)] & ~0xFFFull);
    uint64_t* pd  = (uint64_t*)(pdp [PDP_INDEX(virt)]  & ~0xFFFull);
    uint64_t* pt  = (uint64_t*)(pd  [PD_INDEX(virt)]   & ~0xFFFull);

    uint64_t* pte = &pt[PT_INDEX(virt)];

    // set bits 59-62
    *pte &= ~(0xFULL << 59);   // clear old key bits [62:59]
    *pte |= PTE_PKEY(pkey);   // set new key
    *pte |= PTE_USER;         // makes this a user-mode page;
                               // PKRU is now enforced for all
                               // accesses (supervisor and user)

    // invalidate TLB for this address
    __asm__ volatile("invlpg (%0)" :: "r" (virt) : "memory");
}
/* -----------------------------------------------------------------------
 * vmm_protect_driver — assign MPK Key 1 to ALL e1000 driver pages.
 *
 * This covers both the .secure_driver_code section (e1000 functions
 * annotated with SECURE_DRIVER_CODE) and the .secure_driver_data section
 * (DMA rings annotated with SECURE_DRIVER_DATA).
 *
 * After this function returns:
 *   - Any page in either section is tagged with protection key 1.
 *   - While PKRU has Key 1's AD bit set (default kernel state), the CPU
 *     will raise a #PF on any read or write to those pages from XMPP
 *     code, even though they share the same virtual address space.
 *
 * BUG FIX vs. original:
 *   The original only iterated __secure_driver_data_start/.._end.
 *   Driver CODE pages were left with key 0 (no protection), meaning
 *   XMPP code could still overwrite e1000 function bodies directly.
 *   Now both ranges are protected.
 * ----------------------------------------------------------------------- */
void vmm_protect_driver(void) {
    serial_print("[VMM] Locking e1000 driver...\n");

    /* ── Protect code section ── */
    uint64_t code_start = (uint64_t)&__secure_driver_code_start;
    uint64_t code_end = (uint64_t)&__secure_driver_code_end;

    serial_print("[VMM]   Code range: 0x");
    serial_print_hex(code_start);
    serial_print(" - 0x");
    serial_print_hex(code_end);
    serial_print("\n");

    for (uint64_t addr = code_start; addr < code_end; addr += PAGE_SIZE) {
        vmm_set_pkey(addr, 1); // Key 1 = Secure Driver
    }

    /* ── Protect data section ── */
    uint64_t data_start = (uint64_t)&__secure_driver_data_start;
    uint64_t data_end = (uint64_t)&__secure_driver_data_end;

    serial_print("[VMM]   Data range: 0x");
    serial_print_hex(data_start);
    serial_print(" - 0x");
    serial_print_hex(data_end);
    serial_print("\n");

    for (uint64_t addr = data_start; addr < data_end; addr += PAGE_SIZE){
        vmm_set_pkey(addr, 1);
    }

    serial_print("[VMM] Driver locked. Key 1 required for access.\n");
}