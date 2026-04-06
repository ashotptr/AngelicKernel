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
 *
 * IMPORTANT: ata_init() now returns a bitmask indicating which drives were
 * detected (bit 0 = master, bit 1 = slave).  We check whether ATA_DATA_DRIVE
 * (the slave, bit 1) is actually present before activating the ATA backend.
 * Previously, the ATA backend was always activated on AHCI failure — even
 * when no ATA drive existed — causing every subsequent read/write call to spin
 * through the full BSY timeout before returning -1.
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

    /* ---- Try AHCI first ---- */
    if (ahci_init() == 0) {
        g_backend = DISK_AHCI;
        serial_print("[DISK] Backend: AHCI (DMA, 48-bit LBA)\n");
        return DISK_AHCI;
    }

    /* ---- Fall back to ATA PIO ---- */
    serial_print("[DISK] AHCI unavailable — trying ATA PIO\n");

    /*
     * ata_init() probes both master and slave on the primary IDE channel
     * and returns a bitmask:
     *   bit 0 = master (drive 0) detected as an ATA drive
     *   bit 1 = slave  (drive 1) detected as an ATA drive
     *   0     = no ATA drive found
     *
     * ATA_DATA_DRIVE (defined in ata.h) is ATA_DRIVE_SLAVE = 1.
     * We only activate the ATA backend if that specific drive is present.
     * Using any other drive as the data disk would risk touching the boot
     * image on the master.
     */
    int ata_drives = ata_init();

    if (ata_drives & (1 << ATA_DATA_DRIVE)) {
        g_backend = DISK_ATA_PIO;
        serial_print("[DISK] Backend: ATA PIO (polling, 28-bit LBA)\n");
        return DISK_ATA_PIO;
    }

    if (ata_drives == 0) {
        serial_print("[DISK] ATA: no drives found — persistence disabled\n");
    } else {
        /* ata_init found drives, but not on the expected slot.  The master
         * (drive 0) may be present but we deliberately avoid it because it
         * holds the boot FAT image.  Report this to the operator so they
         * know to re-check the disk wiring or the ATA_DATA_DRIVE constant. */
        serial_print("[DISK] ATA: data drive (slave) not found — persistence disabled\n");
        serial_print("[DISK]      (master detected; check ATA_DATA_DRIVE in ata.h)\n");
    }

    /* g_backend remains DISK_NONE */
    return DISK_NONE;
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
             * write, giving the same durability guarantee as a direct fsync.
             */
            return ata_write_sectors(ATA_DATA_DRIVE, (uint32_t)lba, count, buf);

        default:
            return -1;   /* DISK_NONE */
    }
}