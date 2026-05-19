#ifndef DISK_H
#define DISK_H

#include <stdint.h>

typedef enum {
    DISK_NONE = 0,
    DISK_ATA_PIO = 1,
    DISK_AHCI = 2,
} disk_backend_t;

disk_backend_t disk_init(void);

disk_backend_t disk_backend(void);

int disk_read_sectors (uint64_t lba, uint8_t count, void *buf);

int disk_write_sectors(uint64_t lba, uint8_t count, const void *buf);

#endif