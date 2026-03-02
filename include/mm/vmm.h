#ifndef VMM_H
#define VMM_H

#include <stdint.h>

// Page Table Flags
#define PTE_PRESENT   (1ull << 0)
#define PTE_WRITE     (1ull << 1)
#define PTE_USER      (1ull << 2)
#define PTE_HUGE      (1ull << 7)  // For 2MB pages
#define PTE_NX        (1ull << 63) // No Execute

// INTEL MPK KEYS (Bits 59-62)
// We shift the key value (0-15) by 59 bits to place it in the PTE
#define PTE_PKEY(k)   ((uint64_t)(k) << 59)

void vmm_init();
void vmm_protect_driver(void);

// Map a virtual address to a physical address
// virt: Virtual Address
// phys: Physical Address
// flags: Permissions (Read/Write, MPK Key, etc.)
void vmm_map_page(uint64_t virt, uint64_t phys, uint64_t flags);

#endif