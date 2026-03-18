/* ===========================================================================
 * ata.c — ATA PIO 28-bit LBA driver
 *
 * Talks directly to the primary IDE channel I/O ports (0x1F0–0x1F7, 0x3F6).
 * Works after ExitBootServices because it uses in/out instructions, not UEFI.
 *
 * Tested under QEMU pc (i440fx) with:
 *   -drive file=data.img,format=raw,if=ide,index=1,media=disk
 *
 * On real hardware, any SATA controller configured by the BIOS in "IDE
 * compatibility mode" exposes the same 0x1F0 port interface.
 *
 * SPEC REFERENCES
 *   [ATA]   ATA8-ACS (AT Attachment - 8 - ATA/ATAPI Command Set)
 *           INCITS 452-2009, available at http://www.t13.org
 *   [OSDEV] https://wiki.osdev.org/ATA_PIO_Mode
 * =========================================================================== */

#include "drivers/ata.h"
#include <stdint.h>
#include <string.h>

extern void serial_print (const char *s);
extern void serial_print_hex(uint64_t n);

/* ---- I/O port helpers ---- */
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

/* =========================================================================
 * Primary ATA channel I/O port addresses
 *
 * The primary channel is hardwired at 0x1F0 (command block) and 0x3F6
 * (control block) during the PC ISA/AT era and maintained for compatibility.
 * The secondary channel is at 0x170/0x376 (not used here).
 * Source: OSDEV §"Primary/Secondary Bus"; ATA8-ACS §A (Legacy Registers).
 * ========================================================================= */
#define ATA_DATA 0x1F0  /* Data register (16-bit R/W)                   */
#define ATA_ERR_FEAT 0x1F1  /* Error register (R) / Features register (W)   */
#define ATA_SECTOR_CNT 0x1F2  /* Sector Count — number of sectors to transfer */
#define ATA_LBA_LO 0x1F3  /* LBA bits  7:0                                */
#define ATA_LBA_MID 0x1F4  /* LBA bits 15:8                                */
#define ATA_LBA_HI 0x1F5  /* LBA bits 23:16                               */
/*
 * Drive/Head register (0x1F6) bit layout for LBA28 mode:
 *   bits 3:0 — LBA bits 27:24 (top nibble of the 28-bit address)
 *   bit  4   — Drive select: 0 = master (drive 0), 1 = slave (drive 1)
 *   bit  5   — Obsolete, must be 1 for backwards compatibility
 *   bit  6   — LBA mode: 1 = LBA addressing, 0 = CHS addressing
 *   bit  7   — Obsolete, must be 1 for backwards compatibility
 * The constant 0xE0 sets bits 7, 6, 5 and leaves bits 4 and 3:0 for callers.
 * Source: ATA8-ACS §7.2.1 Table 12 "Device register"; OSDEV §"Drive/Head Reg"
 */
#define ATA_DRIVE_HEAD 0x1F6
#define ATA_STATUS_CMD 0x1F7  /* Status register (R) / Command register (W)   */
/*
 * Alternate Status register (0x3F6): identical content to 0x1F7 but reading
 * it does NOT clear a pending interrupt, making it safe to poll in PIO mode
 * without accidentally ACKing an IRQ.  We use it solely to generate the
 * 400 ns delay described below.
 * Source: ATA8-ACS §A.1; OSDEV §"Alternate Status Register".
 */
#define ATA_ALT_STATUS  0x3F6

/* =========================================================================
 * Status register bit masks — ATA8-ACS §A.1 Table A-2 "Status Register"
 * ========================================================================= */
#define ATA_SR_BSY 0x80  /* Busy: drive is executing a command               */
#define ATA_SR_DRDY 0x40  /* Device Ready: drive is ready to accept commands  */
#define ATA_SR_DRQ 0x08  /* Data Request: drive is ready for a data transfer */
#define ATA_SR_ERR 0x01  /* Error: an error occurred; see Error register      */

/* =========================================================================
 * ATA command opcodes
 * Source: ATA8-ACS (INCITS 452-2009)
 *   0x20 — READ SECTORS      §7.22  (28-bit LBA PIO read)
 *   0x30 — WRITE SECTORS     §7.52  (28-bit LBA PIO write)
 *   0xE7 — FLUSH CACHE       §7.12  (flush volatile write cache to media)
 *   0xEC — IDENTIFY DEVICE   §7.16  (return 512-byte identity block)
 * ========================================================================= */
#define ATA_CMD_READ_SECTORS 0x20
#define ATA_CMD_WRITE_SECTORS 0x30
#define ATA_CMD_FLUSH_CACHE 0xE7
#define ATA_CMD_IDENTIFY 0xEC


/* ===========================================================================
 * ata_400ns_delay
 *
 * After writing the Command register (0x1F7) the ATA spec requires a minimum
 * 400 ns settle time before the status bits are valid.  The standard technique
 * is to read the Alternate Status register (0x3F6) four times — each I/O port
 * read takes at least 100 ns on ISA-speed buses, giving ≥400 ns total.
 * Reading AltStatus instead of Status avoids accidentally ACKing a pending IRQ.
 *
 * The same delay is required after a drive-select write to port 0x1F6, to
 * give the selected drive time to assert its signals on the bus.
 *
 * Source: ATA8-ACS §A.1 "Alternate Status register"; OSDEV §"400ns delays".
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
 * Spin-poll the Status register until the BSY (Busy) bit clears.
 * BSY must be clear before writing any register other than the Device Control
 * register.  Source: ATA8-ACS §7.1 "Command protocol".
 *
 * Timeout rationale: under TCG emulation in QEMU the loop runs at roughly
 * 1–10 MIPS, so 0x10000000 (268 M) iterations gives several seconds of
 * real-wall time — more than enough for any emulated drive.  On real hardware
 * at 3 GHz with ~1 ns per inb this is ~268 ms, still reasonable.  The
 * original 0x100000 value proved too short under TCG.
 *
 * Returns 0 on success, -1 on timeout.
 * =========================================================================== */
static int ata_wait_not_busy(void) {
    for (uint32_t i = 0; i < 0x10000000u; i++) {
        if (!(inb(ATA_STATUS_CMD) & ATA_SR_BSY)) {
            return 0;
        }
    }

    serial_print("[ATA] ERROR: BSY timeout\n");

    return -1;
}


/* ===========================================================================
 * ata_wait_drq
 *
 * After issuing a read or write command, spin until DRQ (Data Request) is set,
 * meaning the drive has a sector buffered and ready for transfer.  Also
 * returns early if ERR is set, indicating a command failure.
 *
 * Note: BSY should already be clear before calling this; BSY and DRQ are
 * mutually exclusive in normal operation (BSY=1 means status is undefined).
 * Source: ATA8-ACS §7.1 Table 3 "Command completion" timing.
 *
 * Returns 0 on success (DRQ set), -1 on error.
 * =========================================================================== */
static int ata_wait_drq(void) {
    for (uint32_t i = 0; i < 0x10000000u; i++) {
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
 * Write the Drive/Head register (0x1F6) to select master or slave and to
 * load the top four bits of a 28-bit LBA address.
 *
 * Must be followed by ata_400ns_delay() to give the drive time to assert its
 * status signals before any further register reads.
 * Source: ATA8-ACS §7.2.1; OSDEV §"Drive/Head Register".
 * =========================================================================== */
static void ata_select_drive(int drive, uint32_t lba) {
    /*
     * 0xE0 = 1110_0000b:
     *   bit 7 = 1 (obsolete, must be 1)
     *   bit 6 = 1 (LBA mode)
     *   bit 5 = 1 (obsolete, must be 1)
     *   bit 4 = drive select (0=master, 1=slave)
     *   bits 3:0 = LBA[27:24]
     */
    uint8_t val = (uint8_t)(0xE0u | ((drive & 1) << 4) | ((lba >> 24) & 0x0Fu));

    outb(ATA_DRIVE_HEAD, val);
}


/* ===========================================================================
 * ata_init
 *
 * Sends the IDENTIFY DEVICE command (0xEC) to both master and slave on the
 * primary channel.  Prints model string and sector count to the serial console.
 *
 * IDENTIFY protocol (ATA8-ACS §7.16):
 *   1. Select drive, zero LBA/count registers.
 *   2. Send IDENTIFY command.
 *   3. If Status = 0x00, no drive present.
 *   4. Poll BSY clear.
 *   5. Check LBA Mid (0x1F4) and LBA Hi (0x1F5): non-zero means ATAPI device.
 *      ATAPI drives write 0x14/0xEB to those ports — not ATA.
 *   6. Poll DRQ set.
 *   7. Read 256 × 16-bit words from the Data port.
 * =========================================================================== */
void ata_init(void) {
    serial_print("[ATA] Initialising primary channel...\n");

    for (int drive = 0; drive <= 1; drive++) {
        ata_select_drive(drive, 0);

        ata_400ns_delay();

        /* Zero registers as required by IDENTIFY protocol.
         * Source: ATA8-ACS §7.16 "IDENTIFY DEVICE". */
        outb(ATA_SECTOR_CNT, 0);
        outb(ATA_LBA_LO, 0);
        outb(ATA_LBA_MID, 0);
        outb(ATA_LBA_HI, 0);

        outb(ATA_STATUS_CMD, ATA_CMD_IDENTIFY);

        ata_400ns_delay();

        /* A status of 0x00 means nothing is present on this slot.
         * Source: OSDEV §"Floating Bus". */
        uint8_t status = inb(ATA_STATUS_CMD);

        if (status == 0) {
            serial_print(drive == 0 ? "[ATA] Master: not present\n"
                                    : "[ATA] Slave:  not present\n");

            continue;
        }

        if (ata_wait_not_busy() != 0) {
            continue;
        }

        /* ATAPI detection: after IDENTIFY, ATA drives leave LBAmid/LBAhi = 0.
         * ATAPI (CD/DVD) drives write 0x14/0xEB respectively.
         * Source: ATA8-ACS §7.16.4; OSDEV §"IDENTIFY command — Command Aborted". */
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

        /* Read the 256-word IDENTIFY response from the data port.
         * Source: ATA8-ACS §7.16.7 "IDENTIFY DEVICE data". */
        uint16_t id[256];

        for (int i = 0; i < 256; i++) {
            id[i] = inw(ATA_DATA);
        }

        /*
         * Words 27–46: Model number string, 40 ASCII characters.
         * Each word stores two characters with the bytes SWAPPED — i.e. the
         * character in the high byte of each word comes first in the string.
         * Source: ATA8-ACS §7.16.7 Table 45, words 27–46
         *         "Model number (byte-swapped ASCII string)".
         */
        char model[41];

        for (int i = 0; i < 20; i++) {
            model[i*2] = (char)(id[27 + i] >> 8);    /* high byte first */
            model[i*2+1] = (char)(id[27 + i] & 0xFF);  /* low byte second */
        }

        model[40] = '\0';
        /* Trim trailing spaces */
        for (int i = 39; i >= 0 && model[i] == ' '; i--) {
            model[i] = '\0';
        }

        /*
         * Words 60–61: Total number of user-addressable logical sectors
         * for 28-bit LBA commands.  Stored as a 32-bit little-endian value
         * split across two 16-bit words: word 60 is the low half, word 61 the
         * high half.  Non-zero value also confirms LBA28 support.
         * Source: ATA8-ACS §7.16.7 Table 45, words 60–61
         *         "Total number of user addressable logical sectors for
         *          28-bit commands (DWord)".
         */
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
 * Reads 'count' sectors (512 B each) from 28-bit 'lba' on 'drive' into 'buf'.
 * Uses PIO 28-bit LBA mode (READ SECTORS command, 0x20).
 *
 * Protocol (OSDEV §"28 bit PIO"):
 *   1. Wait for BSY to clear.
 *   2. Write Drive/Head (LBA[27:24] + drive + LBA flag).
 *   3. Write sector count and LBA[23:0] to 0x1F2–0x1F5.
 *   4. Issue READ SECTORS (0x20) to 0x1F7.
 *   5. For each sector: wait BSY clear, wait DRQ set, read 256 words.
 *   6. 400 ns delay between sectors.
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

        /* Read one sector: 256 × 16-bit words = 512 bytes.
         * Source: ATA8-ACS §7.22 "READ SECTORS". */
        for (int w = 0; w < 256; w++) {
            *p++ = inw(ATA_DATA);
        }

        /* After each sector transfer, give the drive 400 ns to update its
         * BSY/DRQ bits for the next sector.
         * Source: OSDEV §"Note for polling PIO drivers". */
        ata_400ns_delay();
    }

    return 0;
}


/* ===========================================================================
 * ata_write_sectors
 *
 * Writes 'count' sectors from 'buf' to 28-bit 'lba' on 'drive'.
 * Uses PIO 28-bit LBA mode (WRITE SECTORS command, 0x30).
 *
 * Protocol (OSDEV §"Writing 28 bit LBA"):
 *   1. Wait for BSY to clear.
 *   2. Write Drive/Head, sector count, and LBA.
 *   3. Issue WRITE SECTORS (0x30).
 *   4. For each sector: wait BSY clear, wait DRQ set, write 256 words.
 *   5. Issue FLUSH CACHE (0xE7) after all sectors.
 *
 * FLUSH CACHE is mandatory: drives have volatile write buffers that survive
 * only while power is applied.  Without FLUSH CACHE a power loss after a
 * write command returns success can still result in data loss.
 * Source: ATA8-ACS §7.12 "FLUSH CACHE"; OSDEV §"Cache Flush".
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

        /* Write one sector: 256 × 16-bit words = 512 bytes.
         * Note: unlike reads, writes must NOT use REP OUTSW — a small delay
         * between words is required on some hardware.  The single outw call
         * per word naturally provides this.
         * Source: OSDEV §"Writing 28 bit LBA" ("Do not use REP OUTSW"). */
        for (int w = 0; w < 256; w++) {
            outw(ATA_DATA, *p++);
        }

        ata_400ns_delay();
    }

    /* Issue FLUSH CACHE to force the drive's write buffer to persistent media.
     * FLUSH CACHE does not use LBA or sector count registers; only the drive
     * select matters.  We re-assert the drive select with LBA=0 to leave the
     * registers in a clean state.
     * Source: ATA8-ACS §7.12; OSDEV §"Cache Flush". */
    if (ata_wait_not_busy() != 0) {
        return -1;
    }

    ata_select_drive(drive, 0);   /* re-assert drive select; LBA fields unused by FLUSH */

    ata_400ns_delay();

    outb(ATA_STATUS_CMD, ATA_CMD_FLUSH_CACHE);

    ata_400ns_delay();

    if (ata_wait_not_busy() != 0) {
        serial_print("[ATA] WARNING: FLUSH CACHE timeout\n");

        return -1;
    }

    return 0;
}