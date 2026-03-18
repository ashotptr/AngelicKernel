/* ===========================================================================
 * disk.c — Backend-agnostic disk I/O abstraction
 *
 * Tries AHCI first (DMA, 48-bit LBA, modern).  Falls back to ATA PIO
 * (polling, 28-bit LBA, legacy) when no AHCI controller is present.
 * =========================================================================== */

#include "drivers/disk.h"
#include "drivers/ahci.h"
#include "drivers/ata.h"

extern void serial_print(const char *s);

static disk_backend_t g_backend = DISK_NONE;

/* =========================================================================
 * disk_init
 * ========================================================================= */
disk_backend_t disk_init(void) {
    serial_print("[DISK] Probing storage backends...\n");

    /* --- Attempt AHCI --- */
    if (ahci_init() == 0) {
        g_backend = DISK_AHCI;

        serial_print("[DISK] Backend: AHCI (DMA, 48-bit LBA)\n");

        return DISK_AHCI;
    }

    /* --- Fall back to ATA PIO --- */
    serial_print("[DISK] AHCI unavailable — trying ATA PIO\n");

    ata_init();   /* prints model / sector count to serial */

    g_backend = DISK_ATA_PIO;

    serial_print("[DISK] Backend: ATA PIO (polling, 28-bit LBA)\n");

    return DISK_ATA_PIO;
}

disk_backend_t disk_backend(void) {
    return g_backend;
}

/* =========================================================================
 * disk_read_sectors
 * ========================================================================= */
int disk_read_sectors(uint64_t lba, uint8_t count, void *buf) {
    switch (g_backend) {
        case DISK_AHCI:
            return ahci_read_sectors(lba, (uint16_t)count, buf);

        case DISK_ATA_PIO:
            /* ATA PIO driver expects (drive, lba, count, buf).
            * ATA_DATA_DRIVE is defined in ata.h as ATA_DRIVE_SLAVE. */
            return ata_read_sectors(ATA_DATA_DRIVE, (uint32_t)lba, count, buf);

        default:
            return -1;
    }
}

/* =========================================================================
 * disk_write_sectors
 * ========================================================================= */
int disk_write_sectors(uint64_t lba, uint8_t count, const void *buf) {
    switch (g_backend) {
        case DISK_AHCI:
            return ahci_write_sectors(lba, (uint16_t)count, buf);

        case DISK_ATA_PIO:
            /* ata_write_sectors issues ATA FLUSH CACHE (0xE7) after writing,
            * so we get the same durability guarantee as in the original code. */
            return ata_write_sectors(ATA_DATA_DRIVE, (uint32_t)lba, count, buf);

        default:
            return -1;
    }
}
