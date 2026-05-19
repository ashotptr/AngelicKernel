#ifndef VMM_H
#define VMM_H

#include <stdint.h>

#define PTE_PRESENT (1ull << 0)
#define PTE_WRITE (1ull << 1)
#define PTE_USER (1ull << 2)
#define PTE_HUGE (1ull << 7)
#define PTE_NX (1ull << 63)
#define PTE_PKEY(k) ((uint64_t)(k) << 59)

void vmm_init();
void vmm_protect_driver(void);
void vmm_map_page(uint64_t virt, uint64_t phys, uint64_t flags);

#endif