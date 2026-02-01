#include <efi.h>
#include <efilib.h>

#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

static uint32_t pci_read(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t address;
    uint32_t lbus  = (uint32_t)bus;
    uint32_t lslot = (uint32_t)slot;
    uint32_t lfunc = (uint32_t)func;

    address = (uint32_t)((lbus << 16) | (lslot << 11) | (lfunc << 8) | (offset & 0xFC) | ((uint32_t)0x80000000));

    __asm__ volatile("outl %0, %1" : : "a"(address), "Nd"((uint16_t)PCI_CONFIG_ADDRESS));
    
    uint32_t tmp = 0;
    __asm__ volatile("inl %1, %0" : "=a"(tmp) : "Nd"((uint16_t)PCI_CONFIG_DATA));
    
    return tmp;
}

uint64_t pci_get_bar(uint16_t vendor_id, uint16_t device_id) {
    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint16_t slot = 0; slot < 32; slot++) {
            for (uint16_t func = 0; func < 8; func++) {
                uint32_t pci_vendor_device = pci_read(bus, slot, func, 0x00);

                uint16_t actual_vendor = (uint16_t)(pci_vendor_device & 0xFFFF);
                uint16_t actual_device = (uint16_t)(pci_vendor_device >> 16);

                if (actual_vendor == vendor_id) {
                    if (actual_device == device_id) {
                        uint32_t bar0 = pci_read(bus, slot, func, 0x10);
                        
                        return bar0 & 0xFFFFFFF0;
                    }
                }
            }
        }
    }

    return 0;
}
//Memory Mapped (ECAM)