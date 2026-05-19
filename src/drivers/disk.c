#include "drivers/disk.h"
#include "drivers/ahci.h"
#include "drivers/ata.h"

extern void serial_print(const char *s);

static disk_backend_t g_backend = DISK_NONE;

disk_backend_t disk_init(void) {
    serial_print("[disk] probing storage backends\n");

    if (ahci_init() == 0) {
        g_backend = DISK_AHCI;

        serial_print("[disk] backend: ahci (dma, 48-bit lba)\n");
        
        return DISK_AHCI;
    }

    serial_print("[disk] ahci unavailable, trying ata pio\n");

    int ata_drives = ata_init();

    if (ata_drives & (1 << ATA_DATA_DRIVE)) {
        g_backend = DISK_ATA_PIO;

        serial_print("[disk] backend: ata pio (polling, 28-bit lba)\n");
        
        return DISK_ATA_PIO;
    }

    if (ata_drives == 0) {
        serial_print("[disk] ata: no drives found, persistence disabled\n");
    }
    else {
        serial_print("[disk] ata: data drive (slave) not found, persistence disabled\n");
    }

    return DISK_NONE;
}

disk_backend_t disk_backend(void) {
    return g_backend;
}

int disk_read_sectors(uint64_t lba, uint8_t count, void *buf) {
    switch (g_backend) {
        case DISK_AHCI:
            return ahci_read_sectors(lba, (uint16_t)count, buf);

        case DISK_ATA_PIO:
            return ata_read_sectors(ATA_DATA_DRIVE, (uint32_t)lba, count, buf);

        default:
            return -1;
    }
}

int disk_write_sectors(uint64_t lba, uint8_t count, const void *buf) {
    switch (g_backend) {
        case DISK_AHCI:
            return ahci_write_sectors(lba, (uint16_t)count, buf);

        case DISK_ATA_PIO:
            return ata_write_sectors(ATA_DATA_DRIVE, (uint32_t)lba, count, buf);

        default:
            return -1;
    }
}