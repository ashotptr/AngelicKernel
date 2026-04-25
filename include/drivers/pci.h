#ifndef PCI_H
#define PCI_H

#include <stdint.h>

/* ---------------------------------------------------------------------------
 * pci_get_bar — find a specific vendor:device and return its MMIO BAR0.
 * Used by the AHCI scanner and any caller with a known PCI ID.
 * --------------------------------------------------------------------------- */
uint64_t pci_get_bar(uint16_t vendor_id, uint16_t device_id);

/* ---------------------------------------------------------------------------
 * pci_find_nic — scan for any NIC in the ANGELIC_NIC_IDS table (config.h).
 *
 * This is the preferred entry point in kernel.c.  It tries every supported
 * 8254x device ID in order and returns the first match.
 *
 *   matched_did  — if non-NULL, receives the device ID that was found.
 *                  Useful for logging which physical chip is present.
 *
 * Returns the 64-bit MMIO base address, or 0 if no supported NIC is found.
 * --------------------------------------------------------------------------- */
uint64_t pci_find_nic(uint16_t *matched_did);

#endif /* PCI_H */