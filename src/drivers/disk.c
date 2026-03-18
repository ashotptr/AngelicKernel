/* ===========================================================================
 * disk.c — Backend-agnostic disk I/O abstraction
 *
 * Tries AHCI first (DMA, 48-bit LBA, modern hardware).  Falls back to
 * ATA PIO (polling, 28-bit LBA, legacy IDE) when no AHCI controller is found.
 *
 * If both probes fail, g_backend remains DISK_NONE.  All subsequent calls to
 * disk_read_sectors / disk_write_sectors return -1 silently.  The caller
 * (xmpp_persist.c) treats a non-zero return as a disk error, so persistence
 * simply won't work — but the server will still boot and run without crashing.
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

    /* Try AHCI first: PCI scan for class=01h/sub=06h/pi=01h controller. */
    if (ahci_init() == 0) {
        g_backend = DISK_AHCI;

        serial_print("[DISK] Backend: AHCI (DMA, 48-bit LBA)\n");

        return DISK_AHCI;
    }

    /* Fall back to ATA PIO on the primary IDE channel (0x1F0). */
    serial_print("[DISK] AHCI unavailable — trying ATA PIO\n");

    ata_init();   /* prints model / sector count to serial console */

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
            /*
             * ATA_DATA_DRIVE is defined in ata.h as ATA_DRIVE_SLAVE (1).
             * The slave is used so the boot FAT image on the master is
             * never touched.
             */
            return ata_read_sectors(ATA_DATA_DRIVE, (uint32_t)lba, count, buf);

        default:
            return -1;   /* DISK_NONE — no backend initialised */
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
            /*
             * ata_write_sectors issues ATA FLUSH CACHE (0xE7) after every
             * write, giving the same durability guarantee as the original
             * direct ata_write_sectors calls in xmpp_persist.c.
             */
            return ata_write_sectors(ATA_DATA_DRIVE, (uint32_t)lba, count, buf);

        default:
            return -1;   /* DISK_NONE */
    }
}