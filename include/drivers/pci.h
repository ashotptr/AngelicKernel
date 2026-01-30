#ifndef PCI_H
#define PCI_H

#include <stdint.h>

uint64_t pci_get_bar(uint16_t vendor_id, uint16_t device_id);

#endif