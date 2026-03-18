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
 *                  If found: use DMA transfers via AHCI (48-bit LBA).
 *   2. Try ATA PIO — probe both drives on primary IDE channel (0x1F0).
 *                  If a slave drive is detected: use polling 28-bit LBA.
 *   3. Neither found → g_backend = DISK_NONE.  All subsequent read/write
 *      calls return -1.  The server will boot but persistence is silently
 *      disabled; no crash occurs.  Check serial output at startup to confirm
 *      a backend was selected.
 *
 * The caller (xmpp_persist.c) calls disk_init() once at startup and then
 * uses disk_read_sectors / disk_write_sectors for all I/O.
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
 * Probes for an AHCI controller first; falls back to ATA PIO on the primary
 * IDE channel if none is found.  Prints the chosen backend to the serial
 * console.  Call once at startup, before xmpp_persist_load_all().
 *
 * Returns the selected backend (DISK_NONE on complete failure).
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
 * Maximum 128 sectors per call (64 KB), matching the persist layer's needs.
 *
 * Returns 0 on success, -1 on error or if no backend is initialised.
 */
int disk_read_sectors (uint64_t lba, uint8_t count, void *buf);

/*
 * disk_write_sectors
 *
 * Write 'count' sectors from 'buf' to 'lba'.
 * ATA PIO backend issues FLUSH CACHE (0xE7) after writing for durability.
 * AHCI backend relies on drive write-through for emulated drives; for real
 * hardware with a volatile write cache, add ATA_FLUSH_EXT (0xEA) in
 * ahci.c:port_transfer() after the write DMA completes.
 *
 * Returns 0 on success, -1 on error or if no backend is initialised.
 */
int disk_write_sectors(uint64_t lba, uint8_t count, const void *buf);

#endif /* DISK_H */