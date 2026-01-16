// src/drivers/pci.c
#include <efi.h>
#include <efilib.h>

// Simple PCI Configuration Space access via I/O Ports
#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

static uint32_t pci_read(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t address;
    uint32_t lbus  = (uint32_t)bus;
    uint32_t lslot = (uint32_t)slot;
    uint32_t lfunc = (uint32_t)func;

    // Create configuration address
    address = (uint32_t)((lbus << 16) | (lslot << 11) | (lfunc << 8) | (offset & 0xFC) | ((uint32_t)0x80000000));

    // Write address
    __asm__ volatile("outl %0, %1" : : "a"(address), "Nd"((uint16_t)PCI_CONFIG_ADDRESS));
    
    // Read data
    uint32_t tmp = 0;
    __asm__ volatile("inl %1, %0" : "=a"(tmp) : "Nd"((uint16_t)PCI_CONFIG_DATA));
    
    return tmp;
}

uint64_t pci_get_bar(uint16_t vendor_id, uint16_t device_id) {
    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint16_t slot = 0; slot < 32; slot++) {
            for (uint16_t func = 0; func < 8; func++) {
                uint32_t pci_vendor_device = pci_read(bus, slot, func, 0x00);
                if ((pci_vendor_device & 0xFFFF) == vendor_id && (pci_vendor_device >> 16) == device_id) {
                    
                    // Found it! Read BAR0 (Offset 0x10)
                    uint32_t bar0 = pci_read(bus, slot, func, 0x10);
                    
                    // Mask off the type bits (low 4 bits) to get address
                    return bar0 & 0xFFFFFFF0;
                }
            }
        }
    }
    return 0; // Not found
}