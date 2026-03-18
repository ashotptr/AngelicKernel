#ifndef ATA_H
#define ATA_H

/* ===========================================================================
 * ata.h — ATA PIO 28-bit LBA driver
 *
 * Provides direct sector-level read/write to IDE drives using Programmed I/O
 * (PIO) mode via the x86 I/O port bus.  No DMA, no interrupt; pure polling.
 *
 * This is usable after ExitBootServices because it talks directly to the
 * hardware registers rather than through any UEFI protocol.
 *
 * Hardware layout (Primary channel, standard PC):
 *   0x1F0 — Data register (16-bit, used with rep insw / rep outsw)
 *   0x1F1 — Error register (read) / Features register (write)
 *   0x1F2 — Sector count
 *   0x1F3 — LBA bits  7:0
 *   0x1F4 — LBA bits 15:8
 *   0x1F5 — LBA bits 23:16
 *   0x1F6 — Drive select + LBA bits 27:24
 *             bit 6 = 1: LBA mode
 *             bit 4 = 0: master, 1: slave
 *   0x1F7 — Status register (read) / Command register (write)
 *   0x3F6 — Alternate status (read) / Device control (write)
 *             Reading this port causes the required 400 ns delay
 *
 * ATA_DRIVE_MASTER = 0  (first drive on primary channel)
 * ATA_DRIVE_SLAVE  = 1  (second drive on primary channel — our data disk)
 *
 * Usage:
 *   ata_init();                                  // probe drives
 *   ata_read_sectors(1, 0, 42, buf);             // read 42 sectors from LBA 0
 *   ata_write_sectors(1, 0, 42, buf);            // write 42 sectors from LBA 0
 * =========================================================================== */

#include <stdint.h>

/* Drive numbers on the primary ATA channel */
#define ATA_DRIVE_MASTER 0
#define ATA_DRIVE_SLAVE 1

/*
 * ATA_DATA_DRIVE
 *
 * Which physical drive holds the persistent data disk.  We use the slave
 * (drive 1) so the boot FAT image (drive 0 / master) is never touched.
 * Change to ATA_DRIVE_MASTER if your data disk is on a separate controller.
 */
#define ATA_DATA_DRIVE    ATA_DRIVE_SLAVE

/* ---- Public API ---- */

/*
 * ata_init
 *
 * Sends the IDENTIFY command to both master and slave to check presence and
 * print model/capacity to the serial console.  Call once after serial_init().
 * Not required for read/write to function, but catches wiring issues early.
 */
void ata_init(void);

/*
 * ata_read_sectors
 *
 * Read 'count' 512-byte sectors starting at 28-bit LBA 'lba' from 'drive'
 * into the buffer pointed to by 'buf'.  'buf' must be at least count*512
 * bytes.
 *
 * Returns 0 on success, -1 on error (drive not ready, BSY timeout, ERR set).
 */
int ata_read_sectors (int drive, uint32_t lba, uint8_t count, void *buf);

/*
 * ata_write_sectors
 *
 * Write 'count' 512-byte sectors from 'buf' starting at LBA 'lba' on 'drive'.
 * Issues FLUSH CACHE (0xE7) after writing to force the drive write-buffer to
 * persistent storage.
 *
 * Returns 0 on success, -1 on error.
 */
int ata_write_sectors(int drive, uint32_t lba, uint8_t count, const void *buf);

#endif