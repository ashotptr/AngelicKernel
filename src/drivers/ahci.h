#ifndef AHCI_H
#define AHCI_H

#include <stdint.h>

int ahci_init(void);
int ahci_read_sectors(uint64_t lba, uint16_t count, void *buf);
int ahci_write_sectors(uint64_t lba, uint16_t count, const void *buf);

#endif
