#ifndef PMM_H
#define PMM_H

#include <stdint.h>
#include <efi.h>

#define PAGE_SIZE 4096

void pmm_init(EFI_MEMORY_DESCRIPTOR* mem_map, uint64_t map_size, uint64_t descriptor_size);
void* pmm_alloc_page();
void pmm_free_page(void* address);

#endif