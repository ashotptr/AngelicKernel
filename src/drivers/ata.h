#ifndef ATA_H
#define ATA_H

#include <stdint.h>

#define ATA_DRIVE_MASTER 0
#define ATA_DRIVE_SLAVE 1

#define ATA_DATA_DRIVE ATA_DRIVE_SLAVE

int ata_init(void);

int ata_read_sectors (int drive, uint32_t lba, uint8_t count, void *buf);

int ata_write_sectors(int drive, uint32_t lba, uint8_t count, const void *buf);

#endif