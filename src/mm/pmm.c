#include "mm/pmm.h"
#include <stddef.h>

// Helper to print using your Serial Driver
void serial_print(const char* str);
void serial_print_hex(uint64_t n); // We will add this helper to kernel.c

static uint64_t free_memory_start = 0;
static uint64_t free_memory_end = 0;

void pmm_init(EFI_MEMORY_DESCRIPTOR* mem_map, uint64_t map_size, uint64_t descriptor_size) {
    serial_print("[PMM] Parsing Memory Map...\n");

    uint64_t largest_free_segment = 0;
    uint8_t* ptr = (uint8_t*)mem_map;

    // Scan UEFI map for the biggest chunk of FREE RAM
    for (uint64_t i = 0; i < map_size; i += descriptor_size) {
        EFI_MEMORY_DESCRIPTOR* desc = (EFI_MEMORY_DESCRIPTOR*)(ptr + i);
        
        if (desc->Type == EfiConventionalMemory) {
            uint64_t size = desc->NumberOfPages * PAGE_SIZE;
            if (size > largest_free_segment) {
                largest_free_segment = size;
                free_memory_start = desc->PhysicalStart;
                free_memory_end = desc->PhysicalStart + size;
            }
        }
    }

    // Safety: Move start up by 2MB to ensure we don't overwrite the Kernel itself
    if (free_memory_start < 0x200000) { 
        free_memory_start = 0x200000; 
    }

    serial_print("[PMM] Initialized. Pool: 0x"); 
    serial_print_hex(free_memory_start); 
    serial_print(" - 0x");
    serial_print_hex(free_memory_end);
    serial_print("\n");
}

void* pmm_alloc_page() {
    if (free_memory_start + PAGE_SIZE >= free_memory_end) {
        serial_print("[PMM] PANIC: Out of Memory!\n");
        return NULL;
    }

    void* alloc = (void*)free_memory_start;
    free_memory_start += PAGE_SIZE;
    
    // Zero the memory (Security)
    uint64_t* p = (uint64_t*)alloc;
    for(int i=0; i<512; i++) p[i] = 0;

    return alloc;
}

void pmm_free_page(void* address) {
    // No-op for now. Unikernels rarely free memory.
    (void)address;
}