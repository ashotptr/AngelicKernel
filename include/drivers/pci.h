// include/drivers/pci.h
#ifndef PCI_H
#define PCI_H

#include <stdint.h>

// Scans PCI bus for a device and returns its Base Address Register (MMIO address)
uint64_t pci_get_bar(uint16_t vendor_id, uint16_t device_id);

#endif