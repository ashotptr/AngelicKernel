#ifndef DISK_H
#define DISK_H

/* ===========================================================================
 * disk.h — Backend-agnostic disk I/O abstraction
 *
 * Provides a single read/write API that the persistence layer uses without
 * caring whether the underlying drive is accessed via AHCI or ATA PIO.
 *
 * Initialisation order (called from disk_init):
 *   1. Try AHCI  — PCI scan for class=01h/sub=06h/pi=01h controller.
 *                  If found: use DMA transfers via AHCI.
 *   2. Try ATA PIO — probe both drives on primary IDE channel (0x1F0).
 *                  If a slave drive is detected: use PIO 28-bit LBA.
 *   3. Neither found → disk_init returns DISK_NONE; all subsequent
 *      read/write calls return -1.
 *
 * The caller (xmpp_persist.c) should call disk_init() once at startup
 * and then use disk_read_sectors / disk_write_sectors throughout.
 * =========================================================================== */

#include <stdint.h>

typedef enum {
    DISK_NONE = 0,
    DISK_ATA_PIO = 1,
    DISK_AHCI = 2,
} disk_backend_t;

/*
 * disk_init
 *
 * Probes for an AHCI controller first; falls back to ATA PIO on the
 * primary IDE channel if none is found.  Prints the chosen backend to
 * the serial console.
 *
 * Returns the selected backend (DISK_NONE on complete failure).
 * This also replaces the standalone ata_init() call in kernel.c.
 */
disk_backend_t disk_init(void);

/*
 * disk_backend
 *
 * Returns the currently active backend (useful for diagnostics).
 */
disk_backend_t disk_backend(void);

/*
 * disk_read_sectors
 *
 * Read 'count' sectors (512 B each) from 'lba' into 'buf'.
 * 'lba' is treated as 48-bit by AHCI, 28-bit by ATA PIO.
 * Max 128 sectors per call (64 KB), matching the persist layer's needs.
 *
 * Returns 0 on success, -1 on error.
 */
int disk_read_sectors (uint64_t lba, uint8_t count, void *buf);

/*
 * disk_write_sectors
 *
 * Write 'count' sectors from 'buf' to 'lba'.
 * ATA PIO backend issues FLUSH CACHE after writing; AHCI backend relies
 * on the drive's write-through behaviour (for emulated drives) — add an
 * ATA_FLUSH_EXT command here if you need guaranteed persistence on real
 * spinning rust or an SSD without volatile write cache disabled.
 *
 * Returns 0 on success, -1 on error.
 */
int disk_write_sectors(uint64_t lba, uint8_t count, const void *buf);

#endif
