#ifndef PMM_H
#define PMM_H

#include <stdint.h>
#include <efi.h>

#define PAGE_SIZE 4096

// Initialize the Physical Memory Manager
void pmm_init(EFI_MEMORY_DESCRIPTOR* mem_map, uint64_t map_size, uint64_t descriptor_size);

// Request a free physical page (returns the physical address)
void* pmm_alloc_page();

// Free a physical page (placeholder for now)
void pmm_free_page(void* address);

#endif