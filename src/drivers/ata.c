/* ===========================================================================
 * ata.c — ATA PIO 28-bit LBA driver
 *
 * Talks directly to the primary IDE channel I/O ports.  Works after
 * ExitBootServices because it uses in/out instructions, not UEFI protocols.
 *
 * Tested under QEMU q35 with:
 *   -drive file=data.img,format=raw,if=ide,index=1,media=disk
 *
 * On real hardware any SATA controller in "IDE compatibility mode" (a BIOS
 * option) exposes the same 0x1F0 port interface.
 * =========================================================================== */

#include "drivers/ata.h"
#include <stdint.h>
#include <string.h>

/* ---- Serial console (already implemented in kernel.c) ---- */
extern void serial_print (const char *s);
extern void serial_print_hex(uint64_t n);

/* ---- I/O port helpers (same as kernel.c inline asm) ---- */
static inline void outb(uint16_t port, uint8_t val) {
    __asm__ volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t ret;
    __asm__ volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static inline uint16_t inw(uint16_t port) {
    uint16_t ret;
    __asm__ volatile("inw %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static inline void outw(uint16_t port, uint16_t val) {
    __asm__ volatile("outw %0, %1" : : "a"(val), "Nd"(port));
}

/* ---- ATA primary channel I/O ports ---- */
#define ATA_DATA 0x1F0   /* 16-bit data register                  */
#define ATA_ERR_FEAT 0x1F1   /* Error (r) / Features (w)              */
#define ATA_SECTOR_CNT 0x1F2   /* Sector count                          */
#define ATA_LBA_LO 0x1F3   /* LBA bits  7:0                         */
#define ATA_LBA_MID 0x1F4   /* LBA bits 15:8                         */
#define ATA_LBA_HI 0x1F5   /* LBA bits 23:16                        */
#define ATA_DRIVE_HEAD 0x1F6   /* Drive/head: LBA24-27, drive, LBA mode */
#define ATA_STATUS_CMD 0x1F7   /* Status (r) / Command (w)              */
#define ATA_ALT_STATUS 0x3F6   /* Alternate status — reading = 400 ns   */

/* ---- Status register bits ---- */
#define ATA_SR_BSY 0x80    /* Drive is busy                     */
#define ATA_SR_DRDY 0x40    /* Drive ready                       */
#define ATA_SR_DRQ 0x08    /* Data request (transfer ready)     */
#define ATA_SR_ERR 0x01    /* Error occurred                    */

/* ---- ATA commands ---- */
#define ATA_CMD_READ_SECTORS 0x20
#define ATA_CMD_WRITE_SECTORS 0x30
#define ATA_CMD_FLUSH_CACHE 0xE7
#define ATA_CMD_IDENTIFY 0xEC


/* ===========================================================================
 * ata_400ns_delay
 *
 * Reading the alternate status register four times gives the required 400 ns
 * settling delay the ATA spec mandates after writing the command register.
 * This is the standard technique used by every OS textbook and OsDev Wiki.
 * =========================================================================== */
static void ata_400ns_delay(void) {
    inb(ATA_ALT_STATUS);
    inb(ATA_ALT_STATUS);
    inb(ATA_ALT_STATUS);
    inb(ATA_ALT_STATUS);
}


/* ===========================================================================
 * ata_wait_not_busy
 *
 * Spin until the BSY bit clears or we time out.
 * Returns 0 on success, -1 on timeout.
 * =========================================================================== */
static int ata_wait_not_busy(void) {
    /* A typical timeout seen in OS tutorials: ~0x10000 iterations.
     * At ~1 ns per inb on real hardware this is about 65 µs — enough
     * to cover normal command latency but not so long we hang forever. */
    for (uint32_t i = 0; i < 0x10000000; i++) {  // was 0x100000
        uint8_t status = inb(ATA_STATUS_CMD);

        if (!(status & ATA_SR_BSY)) {
            return 0;
        }
    }

    serial_print("[ATA] ERROR: BSY timeout\n");

    return -1;
}


/* ===========================================================================
 * ata_wait_drq
 *
 * Spin until DRQ (Data Request) is set, meaning the drive is ready to
 * transfer a sector's worth of data.  Also checks for ERR.
 * Returns 0 on success, -1 on error.
 * =========================================================================== */
static int ata_wait_drq(void) {
    for (uint32_t i = 0; i < 0x10000000; i++) {  // was 0x100000
        uint8_t status = inb(ATA_STATUS_CMD);

        if (status & ATA_SR_ERR) {
            serial_print("[ATA] ERROR: drive reported ERR bit\n");

            return -1;
        }

        if (status & ATA_SR_DRQ) {
            return 0;
        }
    }

    serial_print("[ATA] ERROR: DRQ timeout\n");
    
    return -1;
}


/* ===========================================================================
 * ata_select_drive
 *
 * Select master or slave and pre-load the top 4 bits of the LBA address.
 * Must be followed by ata_400ns_delay() before issuing further port writes.
 * =========================================================================== */
static void ata_select_drive(int drive, uint32_t lba) {
    /* Bit pattern:  1 = LBA mode  |  0/1 = master/slave  |  LBA[27:24] */
    uint8_t val = (uint8_t)(0xE0 | ((drive & 1) << 4) | ((lba >> 24) & 0x0F));

    outb(ATA_DRIVE_HEAD, val);
}


/* ===========================================================================
 * ata_init
 *
 * Identify both master and slave drives on the primary channel and print
 * their model string + capacity to the serial console.
 * =========================================================================== */
void ata_init(void) {
    serial_print("[ATA] Initialising primary channel...\n");

    for (int drive = 0; drive <= 1; drive++) {
        /* Select drive, LBA=0 */
        ata_select_drive(drive, 0);

        ata_400ns_delay();

        /* Zero sector count / LBA registers before IDENTIFY */
        outb(ATA_SECTOR_CNT, 0);
        outb(ATA_LBA_LO, 0);
        outb(ATA_LBA_MID, 0);
        outb(ATA_LBA_HI, 0);

        outb(ATA_STATUS_CMD, ATA_CMD_IDENTIFY);

        ata_400ns_delay();

        uint8_t status = inb(ATA_STATUS_CMD);

        if (status == 0) {
            /* No drive present */
            serial_print(drive == 0 ? "[ATA] Master: not present\n"
                                    : "[ATA] Slave:  not present\n");

            continue;
        }

        if (ata_wait_not_busy() != 0) {
            continue;
        }

        /* Check LBA mid/hi to filter out ATAPI devices */
        uint8_t mid = inb(ATA_LBA_MID);
        uint8_t hi = inb(ATA_LBA_HI);

        if (mid != 0 || hi != 0) {
            serial_print(drive == 0 ? "[ATA] Master: ATAPI (ignored)\n"
                                    : "[ATA] Slave:  ATAPI (ignored)\n");

            continue;
        }

        if (ata_wait_drq() != 0) {
            continue;
        }

        /* Read 256 x 16-bit IDENTIFY words */
        uint16_t id[256];
        for (int i = 0; i < 256; i++) {
            id[i] = inw(ATA_DATA);
        }

        /* Words 27-46: model string (big-endian byte pairs — swap each pair) */
        char model[41];

        for (int i = 0; i < 20; i++) {
            model[i*2] = (char)(id[27 + i] >> 8);
            model[i*2+1] = (char)(id[27 + i] & 0xFF);
        }

        model[40] = '\0';
        /* Trim trailing spaces */
        for (int i = 39; i >= 0 && model[i] == ' '; i--) {
            model[i] = '\0';
        }

        /* Words 60-61: 28-bit LBA sector count */
        uint32_t sectors = ((uint32_t)id[61] << 16) | id[60];

        serial_print(drive == 0 ? "[ATA] Master: \"" : "[ATA] Slave:  \"");
        serial_print(model);
        serial_print("\"  sectors=0x");
        serial_print_hex(sectors);
        serial_print("\n");
    }
}


/* ===========================================================================
 * ata_read_sectors
 *
 * Reads 'count' sectors (each 512 bytes) starting at 'lba' from 'drive'
 * into 'buf'.  Uses PIO 28-bit LBA mode.
 *
 * Protocol:
 *   1. Wait for BSY clear
 *   2. Select drive, write LBA and count
 *   3. Issue READ SECTORS command (0x20)
 *   4. For each sector: wait DRQ, read 256 words via rep insw
 *   5. 400 ns delay between sectors
 *
 * Returns 0 on success, -1 on any error.
 * =========================================================================== */
int ata_read_sectors(int drive, uint32_t lba, uint8_t count, void *buf) {
    if (ata_wait_not_busy() != 0) {
        return -1;
    }

    ata_select_drive(drive, lba);

    ata_400ns_delay();

    outb(ATA_SECTOR_CNT, count);
    outb(ATA_LBA_LO, (uint8_t)( lba & 0xFF));
    outb(ATA_LBA_MID, (uint8_t)((lba >> 8) & 0xFF));
    outb(ATA_LBA_HI, (uint8_t)((lba >> 16) & 0xFF));

    outb(ATA_STATUS_CMD, ATA_CMD_READ_SECTORS);

    ata_400ns_delay();

    uint16_t *p = (uint16_t *)buf;

    for (int s = 0; s < count; s++) {
        if (ata_wait_not_busy() != 0) {
            return -1;
        }

        if (ata_wait_drq() != 0) {
            return -1;
        }

        /* Read 256 16-bit words = 512 bytes per sector */
        for (int w = 0; w < 256; w++) {
            *p++ = inw(ATA_DATA);
        }

        ata_400ns_delay();
    }

    return 0;
}


/* ===========================================================================
 * ata_write_sectors
 *
 * Writes 'count' sectors from 'buf' to 'lba' on 'drive'.
 *
 * Protocol:
 *   1. Wait BSY clear
 *   2. Select drive, write LBA and count
 *   3. Issue WRITE SECTORS command (0x30)
 *   4. For each sector: wait DRQ, write 256 words via rep outsw
 *   5. Issue FLUSH CACHE (0xE7) and wait BSY clear
 *
 * The FLUSH CACHE step is critical: without it the written data may remain
 * in the drive's volatile write buffer and not reach the platter/flash on
 * sudden power loss.
 *
 * Returns 0 on success, -1 on any error.
 * =========================================================================== */
int ata_write_sectors(int drive, uint32_t lba, uint8_t count, const void *buf) {
    if (ata_wait_not_busy() != 0) {
        return -1;
    }

    ata_select_drive(drive, lba);

    ata_400ns_delay();

    outb(ATA_SECTOR_CNT, count);
    outb(ATA_LBA_LO, (uint8_t)( lba & 0xFF));
    outb(ATA_LBA_MID, (uint8_t)((lba >> 8) & 0xFF));
    outb(ATA_LBA_HI, (uint8_t)((lba >> 16) & 0xFF));

    outb(ATA_STATUS_CMD, ATA_CMD_WRITE_SECTORS);

    ata_400ns_delay();

    const uint16_t *p = (const uint16_t *)buf;

    for (int s = 0; s < count; s++) {
        if (ata_wait_not_busy() != 0) {
            return -1;
        }

        if (ata_wait_drq() != 0) {
            return -1;
        }

        /* Write 256 16-bit words = 512 bytes per sector */
        for (int w = 0; w < 256; w++) {
            outw(ATA_DATA, *p++);
        }

        ata_400ns_delay();
    }

    /* FLUSH CACHE — force write buffer → persistent storage */
    if (ata_wait_not_busy() != 0) {
        return -1;
    }

    ata_select_drive(drive, 0);          /* re-select to clear LBA fields */

    ata_400ns_delay();

    outb(ATA_STATUS_CMD, ATA_CMD_FLUSH_CACHE);

    ata_400ns_delay();

    if (ata_wait_not_busy() != 0) {
        serial_print("[ATA] WARNING: FLUSH CACHE timeout\n");

        return -1;
    }
    
    return 0;
}
