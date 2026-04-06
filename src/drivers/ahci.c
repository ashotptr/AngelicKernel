/* ===========================================================================
 * ahci.c — AHCI (Serial ATA) host controller driver
 *
 * Supports a single data drive (the first port with a connected device).
 * Uses command slot 0 only (no NCQ, no port multipliers — KISS).
 * All DMA structures are static and identity-mapped.
 *
 * SPEC REFERENCES
 *   [AHCI]  Serial ATA Advanced Host Controller Interface (AHCI) 1.3.1
 *           https://www.intel.com/content/dam/www/public/us/en/documents/
 *           technical-specifications/serial-ata-ahci-spec-rev1-3-1.pdf
 *   [PCI]   PCI Local Bus Specification Revision 3.0
 *   [ATA]   ATA8-ACS (AT Attachment - 8 - ATA/ATAPI Command Set)
 *           INCITS 452-2009, available at t13.org
 *   [OSDEV] https://wiki.osdev.org/AHCI
 * =========================================================================== */

#include "drivers/ahci.h"
#include <stdint.h>
#include <string.h>

extern void serial_print(const char *s);
extern void serial_print_hex(uint64_t n);

/* =========================================================================
 * PCI configuration space access via I/O ports 0xCF8 / 0xCFC
 *
 * The PCI Configuration Address register (0xCF8) format is:
 *   bit 31     : Enable bit — must be 1 for a config cycle
 *   bits 23:16 : Bus number
 *   bits 15:11 : Device (slot) number
 *   bits 10:8  : Function number
 *   bits 7:2   : Register offset (DWORD-aligned; bits 1:0 are always 0)
 *
 * Source: PCI Local Bus Specification rev 3.0, §3.2.2.3.2
 *         "Configuration Mechanism #1"
 * ========================================================================= */
#define PCI_CONFIG_ADDR  0x0CF8u
#define PCI_CONFIG_DATA  0x0CFCu

static inline void outl_pio(uint16_t port, uint32_t val) {
    __asm__ volatile("outl %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint32_t inl_pio(uint16_t port) {
    uint32_t v;
    __asm__ volatile("inl %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

static uint32_t pci_read32(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off) {
    uint32_t addr = (1u << 31)
                  | ((uint32_t)bus << 16)
                  | ((uint32_t)dev << 11)
                  | ((uint32_t)fn  <<  8)
                  | (off & 0xFCu);   /* mask bits 1:0 — must be DWORD aligned */
    outl_pio(PCI_CONFIG_ADDR, addr);
    return inl_pio(PCI_CONFIG_DATA);
}

static void pci_write32(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off, uint32_t val) {
    uint32_t addr = (1u << 31)
                  | ((uint32_t)bus << 16)
                  | ((uint32_t)dev << 11)
                  | ((uint32_t)fn  <<  8)
                  | (off & 0xFCu);
    outl_pio(PCI_CONFIG_ADDR, addr);
    outl_pio(PCI_CONFIG_DATA, val);
}

/* =========================================================================
 * AHCI HBA Generic Host Control register offsets (relative to ABAR)
 *
 * Source: AHCI 1.3.1 §3.1 "Generic Host Control"
 * ========================================================================= */
#define HBA_CAP   0x00u   /* Host Capabilities                  — §3.1.1 */
#define HBA_GHC   0x04u   /* Global Host Control                — §3.1.2 */
#define HBA_IS    0x08u   /* Interrupt Status                   — §3.1.3 */
#define HBA_PI    0x0Cu   /* Ports Implemented bitmask          — §3.1.4 */
#define HBA_VS    0x10u   /* AHCI Version                       — §3.1.5 */
#define HBA_CAP2  0x24u   /* Host Capabilities Extended         — §3.1.10 */
#define HBA_BOHC  0x28u   /* BIOS/OS Handoff Control and Status — §3.1.11 */

/* GHC bit definitions — AHCI 1.3.1 §3.1.2 Table 4 */
#define GHC_AE    (1u << 31)  /* AHCI Enable: must be set for AHCI operation */
#define GHC_IE    (1u <<  1)  /* Interrupt Enable — keep 0; we poll          */
#define GHC_HR    (1u <<  0)  /* HBA Reset: self-clearing after reset done   */

/* CAP bit definitions — AHCI 1.3.1 §3.1.1 */
#define CAP_SSS   (1u <<  2)  /* Staggered Spin-up Supported                 */

/* CAP2 / BOHC bit definitions — AHCI 1.3.1 §3.1.10–11 */
#define CAP2_BOH  (1u <<  0)  /* CAP2: Supports BIOS/OS Handoff             */
#define BOHC_BOS  (1u <<  0)  /* BOHC: BIOS-Owned Semaphore                 */
#define BOHC_OOS  (1u <<  1)  /* BOHC: OS-Owned Semaphore                   */
#define BOHC_BB   (1u <<  4)  /* BOHC: BIOS Busy (BIOS still cleaning up)   */

/* =========================================================================
 * Per-port register offsets
 *
 * Each implemented port occupies 0x80 (128) bytes of register space starting
 * at ABAR + 0x100 + port_index * 0x80.
 *
 * Source: AHCI 1.3.1 §3.3 "Port Registers (one set per port)"
 * ========================================================================= */
#define PORT_CLB   0x00u  /* PxCLB:  Command List Base Address (1 KB aligned) — §3.3.1 */
#define PORT_CLBU  0x04u  /* PxCLBU: Command List Base Address Upper 32 bits  — §3.3.2 */
#define PORT_FB    0x08u  /* PxFB:   FIS Base Address (256 B aligned)         — §3.3.3 */
#define PORT_FBU   0x0Cu  /* PxFBU:  FIS Base Address Upper 32 bits           — §3.3.4 */
#define PORT_IS    0x10u  /* PxIS:   Interrupt Status                         — §3.3.5 */
#define PORT_IE    0x14u  /* PxIE:   Interrupt Enable                         — §3.3.6 */
#define PORT_CMD   0x18u  /* PxCMD:  Command and Status                       — §3.3.7 */
#define PORT_TFD   0x20u  /* PxTFD:  Task File Data                           — §3.3.8 */
#define PORT_SIG   0x24u  /* PxSIG:  Signature                                — §3.3.9 */
#define PORT_SSTS  0x28u  /* PxSSTS: SATA Status (SCR0: SStatus)              — §3.3.10 */
#define PORT_SCTL  0x2Cu  /* PxSCTL: SATA Control (SCR2: SControl)            — §3.3.11 */
#define PORT_SERR  0x30u  /* PxSERR: SATA Error (SCR1: SError)                — §3.3.12 */
#define PORT_SACT  0x34u  /* PxSACT: SATA Active                              — §3.3.13 */
#define PORT_CI    0x38u  /* PxCI:   Command Issue                            — §3.3.14 */

/* PxCMD bit definitions — AHCI 1.3.1 §3.3.7 Table 23 */
#define PCMD_ST   (1u <<  0)  /* Start: set to start DMA command processing          */
#define PCMD_SUD  (1u <<  1)  /* Spin-Up Device: assert to spin up a staggered drive */
#define PCMD_POD  (1u <<  2)  /* Power On Device: assert to power on a cold device   */
#define PCMD_FRE  (1u <<  4)  /* FIS Receive Enable: must be set before CLB/FB write */
#define PCMD_FR   (1u << 14)  /* FIS Receive Running: read-only status bit           */
#define PCMD_CR   (1u << 15)  /* Command List Running: read-only status bit          */

/* PxTFD bits (mirror of the ATA status/error registers) — AHCI 1.3.1 §3.3.8 */
#define TFD_ERR  0x01u   /* ATA ERR bit set by drive on command error */
#define TFD_DRQ  0x08u   /* ATA DRQ bit: drive wants data transfer    */
#define TFD_BSY  0x80u   /* ATA BSY bit: drive is busy                */

/* PxSSTS DET and IPM fields — AHCI 1.3.1 §3.3.10 Table 28 */
#define SSTS_DET_MASK      0x0Fu
#define SSTS_DET_PRESENT   0x03u  /* device present, comm established */
#define SSTS_IPM_MASK      0xF00u
#define SSTS_IPM_ACTIVE    0x100u /* interface in active power state  */

/* PxSIG values — AHCI 1.3.1 §3.3.9
 * The signature identifies the attached device type after initial COMRESET. */
#define SIG_ATA    0x00000101u  /* SATA drive (generic ATA)  */
#define SIG_ATAPI  0xEB140101u  /* ATAPI drive (CD/DVD)      */
#define SIG_SEMB   0xC33C0101u  /* SATA Enclosure Management Bridge */
#define SIG_PM     0x96690101u  /* Port Multiplier           */

/* PxIS bit 30 — Task File Error Status — AHCI 1.3.1 §3.3.5 Table 18 */
#define PIS_TFES (1u << 30)

/* =========================================================================
 * AHCI system-memory data structures
 *
 * Source: AHCI 1.3.1 §4 "System Memory Structures"
 * ========================================================================= */

/* Command Header — one of up to 32 slots in the Command List.
 * Each slot is 32 bytes.  Source: AHCI 1.3.1 §4.2.2 Table 12. */
typedef struct {
    uint16_t flags;
    uint16_t prdtl;
    uint32_t prdbc;
    uint32_t ctba;
    uint32_t ctbau;
    uint32_t _res[4];
} __attribute__((packed)) hba_cmd_hdr_t;

_Static_assert(sizeof(hba_cmd_hdr_t) == 32, "hba_cmd_hdr_t must be 32 bytes");

/* Physical Region Descriptor Table entry — AHCI 1.3.1 §4.2.3 Table 18. */
typedef struct {
    uint32_t dba;
    uint32_t dbau;
    uint32_t _res;
    /*
     * dbc: Byte Count — ZERO-BASED.  A value of 0 means 1 byte.
     * Maximum is 0x3FFFFF (4 MB − 1).
     * Bit 31 = interrupt-on-completion flag (we leave it 0; we poll).
     * Source: AHCI 1.3.1 §4.2.3 Table 18, DW3.
     */
    uint32_t dbc;
} __attribute__((packed)) hba_prdt_t;

_Static_assert(sizeof(hba_prdt_t) == 16, "hba_prdt_t must be 16 bytes");

/* Command Table — pointed to by the Command Header's CTBA field.
 * Layout: Command FIS (64 B) | ATAPI cmd (16 B) | reserved (48 B) | PRDT[]
 * Source: AHCI 1.3.1 §4.2.3 Figure 13. */
typedef struct {
    uint8_t    cfis[64];
    uint8_t    acmd[16];
    uint8_t    _res[48];
    hba_prdt_t prdt[1];   /* one PRDT entry covers our whole transfer */
} __attribute__((packed)) hba_cmd_tbl_t;

/* H2D Register FIS — Register Host-to-Device Frame Information Structure.
 * Source: Serial ATA Revision 3.0 §10.3.1 */
typedef struct {
    uint8_t  fis_type;
    uint8_t  flags;
    uint8_t  command;
    uint8_t  featurel;
    uint8_t  lba0;
    uint8_t  lba1;
    uint8_t  lba2;
    uint8_t  device;
    uint8_t  lba3;
    uint8_t  lba4;
    uint8_t  lba5;
    uint8_t  featureh;
    uint8_t  countl;
    uint8_t  counth;
    uint8_t  icc;
    uint8_t  control;
    uint8_t  _res[4];
} __attribute__((packed)) fis_h2d_t;

_Static_assert(sizeof(fis_h2d_t) == 20, "fis_h2d_t must be 20 bytes");

#define FIS_TYPE_H2D   0x27u   /* H2D Register FIS type byte — SATA Rev 3.0 §10.3 */
#define FIS_FLAG_CMD   0x80u   /* C bit: 1 = command register update */

/* ATA command opcodes — ATA8-ACS (INCITS 452-2009) */
#define ATA_READ_DMA_EXT   0x25u  /* §7.25  48-bit LBA DMA read               */
#define ATA_WRITE_DMA_EXT  0x35u  /* §7.56  48-bit LBA DMA write              */
#define ATA_FLUSH_EXT      0xEAu  /* §7.13  flush volatile write cache (48-bit) */
#define ATA_IDENTIFY       0xECu  /* §7.16  return 512-byte identity block     */

/* =========================================================================
 * Static DMA-capable memory structures
 *
 * Alignment requirements from AHCI 1.3.1:
 *   §3.3.1  PxCLB  — Command List Base must be 1 KB aligned
 *   §3.3.3  PxFB   — FIS Base must be 256 B aligned
 *   §4.2.3  CTBA   — Command Table must be 128 B aligned
 *
 * Under an identity-mapped page table virtual == physical, so the C pointer
 * IS the bus address the HBA should use.
 * ========================================================================= */
static hba_cmd_hdr_t s_cmd_list[32] __attribute__((aligned(1024)));
static uint8_t       s_fis_area[256] __attribute__((aligned(256)));
static hba_cmd_tbl_t s_cmd_tbl       __attribute__((aligned(128)));

/* DMA data buffer — 128 sectors × 512 B = 64 KB.
 * Page-aligned so the physical address is unambiguous in the PRDT. */
#define AHCI_DMA_SECTORS 128u
static uint8_t s_dma_buf[AHCI_DMA_SECTORS * 512] __attribute__((aligned(4096)));

/* =========================================================================
 * Driver state
 * ========================================================================= */
static volatile uint8_t *g_abar = NULL;
static int g_port = -1;

/* =========================================================================
 * MMIO register accessors
 * ========================================================================= */
static inline uint32_t hba_read(uint32_t off) {
    return *(volatile uint32_t *)(g_abar + off);
}

static inline void hba_write(uint32_t off, uint32_t val) {
    *(volatile uint32_t *)(g_abar + off) = val;
}

static inline uint32_t port_read(int p, uint32_t off) {
    return hba_read(0x100u + (uint32_t)p * 0x80u + off);
}

static inline void port_write(int p, uint32_t off, uint32_t val) {
    hba_write(0x100u + (uint32_t)p * 0x80u + off, val);
}

/* =========================================================================
 * Port DMA engine start / stop
 *
 * Stop sequence — AHCI 1.3.1 §10.3.1:
 *   1. Clear PxCMD.ST, wait for PxCMD.CR to clear.
 *   2. Clear PxCMD.FRE, wait for PxCMD.FR to clear.
 *
 * Start sequence — AHCI 1.3.1 §10.3.1:
 *   1. Wait for PxCMD.CR to be clear.
 *   2. Set PxCMD.FRE.
 *   3. Set PxCMD.ST.
 * ========================================================================= */
static void port_stop_engine(int p) {
    port_write(p, PORT_CMD, port_read(p, PORT_CMD) & ~PCMD_ST);
    for (int i = 0; i < 500000; i++) {
        if (!(port_read(p, PORT_CMD) & PCMD_CR)) break;
    }
    port_write(p, PORT_CMD, port_read(p, PORT_CMD) & ~PCMD_FRE);
    for (int i = 0; i < 500000; i++) {
        if (!(port_read(p, PORT_CMD) & PCMD_FR)) break;
    }
}

static void port_start_engine(int p) {
    for (int i = 0; i < 500000; i++) {
        if (!(port_read(p, PORT_CMD) & PCMD_CR)) break;
    }
    port_write(p, PORT_CMD, port_read(p, PORT_CMD) | PCMD_FRE);
    port_write(p, PORT_CMD, port_read(p, PORT_CMD) | PCMD_ST);
}

/* =========================================================================
 * Port initialisation
 *
 * Returns 0 if an ATA drive is present and the port is ready, -1 otherwise.
 * ========================================================================= */
static int port_init(int p) {
    /* Check PxSSTS: device present (DET=3) and interface active (IPM=1).
     * Source: AHCI 1.3.1 §3.3.10 Table 28. */
    uint32_t ssts = port_read(p, PORT_SSTS);
    if ((ssts & SSTS_DET_MASK) != SSTS_DET_PRESENT) return -1;
    if ((ssts & SSTS_IPM_MASK) != SSTS_IPM_ACTIVE)  return -1;

    port_stop_engine(p);

    /* Point CLB and FB at our static structures.
     * Both 32-bit and upper-32-bit registers must be written even when
     * operating in 32-bit physical address space (upper = 0). */
    uint64_t clb_phys = (uint64_t)(uintptr_t)s_cmd_list;
    uint64_t fb_phys  = (uint64_t)(uintptr_t)s_fis_area;

    port_write(p, PORT_CLB,  (uint32_t)( clb_phys        & 0xFFFFFFFFu));
    port_write(p, PORT_CLBU, (uint32_t)( clb_phys >> 32));
    port_write(p, PORT_FB,   (uint32_t)( fb_phys         & 0xFFFFFFFFu));
    port_write(p, PORT_FBU,  (uint32_t)( fb_phys  >> 32));

    /* Zero DMA structures after writing port registers.
     * The HBA may start using them as soon as FRE is set. */
    memset(s_cmd_list, 0, sizeof(s_cmd_list));
    memset(s_fis_area, 0, sizeof(s_fis_area));
    memset(&s_cmd_tbl, 0, sizeof(s_cmd_tbl));

    /* Wire command slot 0 to our single command table. */
    uint64_t ctba_phys = (uint64_t)(uintptr_t)&s_cmd_tbl;
    s_cmd_list[0].ctba  = (uint32_t)( ctba_phys        & 0xFFFFFFFFu);
    s_cmd_list[0].ctbau = (uint32_t)( ctba_phys >> 32);

    /* Clear any stale error and interrupt bits.
     * Writing 1s to IS and SERR clears them (W1C).
     * Source: AHCI 1.3.1 §3.3.5 (PxIS) and §3.3.12 (PxSERR). */
    port_write(p, PORT_SERR, 0xFFFFFFFFu);
    port_write(p, PORT_IS,   0xFFFFFFFFu);

    /* Staggered spin-up: if CAP.SSS is set, assert SUD + POD to wake drive.
     * Source: AHCI 1.3.1 §10.10; §3.3.7 Table 23. */
    if (hba_read(HBA_CAP) & CAP_SSS) {
        port_write(p, PORT_CMD, port_read(p, PORT_CMD) | PCMD_SUD | PCMD_POD);
    }

    /* COMRESET: set PxSCTL.DET=1 for ≥1 ms, then clear to DET=0.
     * Source: AHCI 1.3.1 §10.4.2 "Port Reset". */
    uint32_t sctl = port_read(p, PORT_SCTL);
    port_write(p, PORT_SCTL, (sctl & ~0xFu) | 0x1u);   /* DET=1 */

    for (volatile int i = 0; i < 20000; i++) {         /* ≥1 ms hold */
        (void)port_read(p, PORT_SCTL);
    }

    port_write(p, PORT_SCTL, sctl & ~0xFu);             /* DET=0 */

    /* Wait for DET=3 (device and PHY link re-established). */
    int det_ok = 0;
    for (int i = 0; i < 0x100000; i++) {
        if ((port_read(p, PORT_SSTS) & SSTS_DET_MASK) == SSTS_DET_PRESENT) {
            det_ok = 1;
            break;
        }
    }

    if (!det_ok) {
        return -1;
    }

    /* Verify the port signature identifies an ATA (not ATAPI or PM) device.
     * Source: AHCI 1.3.1 §3.3.9 "Port Signature Register". */
    uint32_t sig = port_read(p, PORT_SIG);
    if (sig != SIG_ATA) {
        serial_print("[AHCI] Port SIG=0x");
        serial_print_hex(sig);
        serial_print(" — not an ATA drive, skipping\n");
        return -1;
    }

    port_start_engine(p);

    /* Wait for TFD to show BSY=0 and DRQ=0 — drive ready for commands.
     * Source: AHCI 1.3.1 §10.3.1. */
    for (int i = 0; i < 0x100000; i++) {
        if (!(port_read(p, PORT_TFD) & (TFD_BSY | TFD_DRQ))) break;
    }

    return 0;
}

/* =========================================================================
 * Poll slot 0 for command completion
 *
 * Checks PxIS.TFES (task-file error) before PxCI (command still pending).
 * On any error the port's interrupt and error registers are cleared so the
 * port is left in a clean state for the next command.
 * ========================================================================= */
static int port_wait_slot0(void) {
    /*
     * PxIS.TFES (bit 30): set if the drive reported an error in PxTFD.ERR.
     * PxCI bit 0: cleared by HBA when slot 0 command completes successfully.
     * Source: AHCI 1.3.1 §3.3.5 (PxIS); §3.3.14 (PxCI).
     */
    for (uint32_t i = 0; i < 0x2000000u; i++) {
        if (port_read(g_port, PORT_IS) & PIS_TFES) {
            serial_print("[AHCI] ERROR: Task File Error (TFD=0x");
            serial_print_hex(port_read(g_port, PORT_TFD));
            serial_print(")\n");

            /* Clear error state so the port is usable for subsequent commands. */
            port_write(g_port, PORT_IS,   0xFFFFFFFFu);
            port_write(g_port, PORT_SERR, 0xFFFFFFFFu);

            return -1;
        }

        if (!(port_read(g_port, PORT_CI) & 1u)) {
            return 0;  /* command completed */
        }
    }

    serial_print("[AHCI] ERROR: command timeout — slot 0 never cleared\n");

    /* Clean up so subsequent commands are not affected. */
    port_write(g_port, PORT_IS,   0xFFFFFFFFu);
    port_write(g_port, PORT_SERR, 0xFFFFFFFFu);

    return -1;
}

/* =========================================================================
 * port_flush
 *
 * Issues ATA FLUSH CACHE EXT (0xEA) to force the drive's volatile write
 * cache to persistent media.  Must be called after every write transfer
 * on real hardware where the drive has a write-back cache.
 *
 * FLUSH CACHE EXT is the 48-bit form; it accepts no data (prdtl=0).
 * Source: ATA8-ACS §7.13 "FLUSH CACHE EXT".
 *
 * Returns 0 on success, -1 on error.
 * ========================================================================= */
static int port_flush(void) {
    /* Wait for the port to be idle before submitting the flush. */
    for (int i = 0; i < 0x100000; i++) {
        if (!(port_read(g_port, PORT_TFD) & (TFD_BSY | TFD_DRQ))) break;
    }

    memset(&s_cmd_tbl, 0, sizeof(s_cmd_tbl));

    fis_h2d_t *fis = (fis_h2d_t *)s_cmd_tbl.cfis;
    fis->fis_type = FIS_TYPE_H2D;
    fis->flags    = FIS_FLAG_CMD;
    fis->command  = ATA_FLUSH_EXT;
    fis->device   = (1u << 6);  /* LBA mode — required for 48-bit commands */

    /*
     * FLUSH CACHE EXT transfers no data, so prdtl = 0.
     * The command header flags still carry CFL=5 (5 DWORDs for the FIS).
     * W=0 since there is no data direction.
     */
    s_cmd_list[0].flags = 5u;   /* CFL=5, A=0, W=0, P=0 */
    s_cmd_list[0].prdtl = 0u;
    s_cmd_list[0].prdbc = 0u;

    port_write(g_port, PORT_IS,   0xFFFFFFFFu);
    port_write(g_port, PORT_SERR, 0xFFFFFFFFu);
    port_write(g_port, PORT_CI,   1u);

    return port_wait_slot0();
}

/* =========================================================================
 * port_transfer — core DMA read/write
 * ========================================================================= */
static int port_transfer(uint64_t lba, uint16_t count, void *buf, int write) {
    if (count == 0 || count > AHCI_DMA_SECTORS) {
        serial_print("[AHCI] ERROR: count out of range\n");
        return -1;
    }

    /* Wait for idle before submitting a new command. */
    for (int i = 0; i < 0x100000; i++) {
        if (!(port_read(g_port, PORT_TFD) & (TFD_BSY | TFD_DRQ))) break;
    }

    uint32_t byte_count = (uint32_t)count * 512u;

    if (write) {
        memcpy(s_dma_buf, buf, byte_count);
    }

    /* Build Command Table */
    memset(&s_cmd_tbl, 0, sizeof(s_cmd_tbl));

    fis_h2d_t *fis = (fis_h2d_t *)s_cmd_tbl.cfis;
    fis->fis_type = FIS_TYPE_H2D;
    fis->flags    = FIS_FLAG_CMD;
    fis->command  = write ? ATA_WRITE_DMA_EXT : ATA_READ_DMA_EXT;
    /*
     * Device register: bit 6 = 1 (LBA mode, mandatory for 48-bit LBA).
     * Bit 4 = 0 (device 0; AHCI port routing handles physical device select).
     * Source: ATA8-ACS §7.2.1 Table 12; AHCI 1.3.1 §4.2.3.
     */
    fis->device   = (1u << 6);

    /* 48-bit LBA split across lba0–lba5 (two shadow register writes per field).
     * Source: ATA8-ACS §7.25 "READ DMA EXT". */
    fis->lba0 = (uint8_t)( lba        & 0xFFu);
    fis->lba1 = (uint8_t)((lba >>  8) & 0xFFu);
    fis->lba2 = (uint8_t)((lba >> 16) & 0xFFu);
    fis->lba3 = (uint8_t)((lba >> 24) & 0xFFu);
    fis->lba4 = (uint8_t)((lba >> 32) & 0xFFu);
    fis->lba5 = (uint8_t)((lba >> 40) & 0xFFu);

    /* Sector count split across countl (bits 7:0) and counth (bits 15:8). */
    fis->countl = (uint8_t)( count       & 0xFFu);
    fis->counth = (uint8_t)((count >> 8) & 0xFFu);

    /* Single PRDT entry pointing at s_dma_buf.
     * dbc is ZERO-BASED: byte_count − 1.  Source: AHCI 1.3.1 §4.2.3. */
    uint64_t dba_phys = (uint64_t)(uintptr_t)s_dma_buf;
    s_cmd_tbl.prdt[0].dba  = (uint32_t)( dba_phys        & 0xFFFFFFFFu);
    s_cmd_tbl.prdt[0].dbau = (uint32_t)( dba_phys >> 32);
    s_cmd_tbl.prdt[0].dbc  = byte_count - 1u;

    /* Build Command Header for slot 0.
     * flags field (AHCI 1.3.1 §4.2.2 Table 12):
     *   [4:0] CFL = 5 (H2D FIS = 20 bytes = 5 DWORDs)
     *   [6]   W   = 1 for write (host→device data flow), 0 for read
     */
    s_cmd_list[0].flags = (uint16_t)(5u | (write ? (1u << 6) : 0u));
    s_cmd_list[0].prdtl = 1u;
    s_cmd_list[0].prdbc = 0u;

    /* Issue command */
    port_write(g_port, PORT_IS,   0xFFFFFFFFu);  /* clear pending interrupts */
    port_write(g_port, PORT_SERR, 0xFFFFFFFFu);  /* clear SATA error register */
    port_write(g_port, PORT_CI,   1u);            /* issue slot 0 */

    if (port_wait_slot0() != 0) {
        return -1;
    }

    if (!write) {
        memcpy(buf, s_dma_buf, byte_count);
    } else {
        /*
         * Issue FLUSH CACHE EXT after every write to force the drive's
         * volatile write cache to persistent media.
         *
         * Without this, a drive with a write-back cache may acknowledge the
         * write DMA command before the data reaches the disk platters.  A
         * power failure at that point causes silent data loss even though the
         * OS received a successful return value.
         *
         * QEMU's SATA emulator ignores the flush (disk images are already
         * written through to the host file), so this adds no latency there.
         * On real SSDs and HDDs the flush time is typically < 5 ms.
         *
         * Source: ATA8-ACS §7.13 "FLUSH CACHE EXT"; AHCI 1.3.1 §5.5.
         */
        if (port_flush() != 0) {
            serial_print("[AHCI] WARNING: FLUSH CACHE EXT failed — data may not be durable\n");
            /* Return success anyway: the write DMA itself succeeded. The
             * flush failure is non-fatal (data is likely in drive cache). */
        }
    }

    return 0;
}

/* =========================================================================
 * pci_find_ahci_abar
 *
 * Scans PCI bus 0 for an AHCI controller:
 *   Class = 0x01 (Mass Storage), Subclass = 0x06 (SATA), ProgIF = 0x01 (AHCI 1.0)
 *
 * Enables Memory Space + Bus Master in the Command register, then returns
 * the 32-bit ABAR (BAR5) physical address.
 * Returns 0 if no controller is found.
 *
 * NOTE: AHCI 1.3.1 §2.1.11 guarantees ABAR is a non-prefetchable 32-bit
 * memory BAR, so reading BAR5 alone is sufficient.
 * ========================================================================= */
static uint64_t pci_find_ahci_abar(void) {
    for (uint8_t dev = 0; dev < 32; dev++) {
        for (uint8_t fn = 0; fn < 8; fn++) {
            uint32_t id = pci_read32(0, dev, fn, 0x00);

            if ((id & 0xFFFFu) == 0xFFFFu) {
                if (fn == 0) break;
                continue;
            }

            uint32_t cc = pci_read32(0, dev, fn, 0x08);
            int is_ahci = ((cc >> 24) & 0xFFu) == 0x01u   /* Mass Storage  */
                       && ((cc >> 16) & 0xFFu) == 0x06u   /* Serial ATA    */
                       && ((cc >>  8) & 0xFFu) == 0x01u;  /* AHCI 1.0      */

            if (!is_ahci) {
                if (fn == 0) {
                    uint32_t ht = pci_read32(0, dev, 0, 0x0C);
                    if (!((ht >> 16) & 0x80u)) break;
                }
                continue;
            }

            /* Enable Memory Space (bit 1) + Bus Master (bit 2). */
            uint32_t cmd_reg = pci_read32(0, dev, fn, 0x04);
            pci_write32(0, dev, fn, 0x04, cmd_reg | 0x06u);

            /* Read ABAR from BAR5 (PCI config offset 0x24).
             * Mask off the 4 attribute bits.  AHCI 1.3.1 §2.1.11. */
            uint64_t abar = pci_read32(0, dev, fn, 0x24) & ~0xFu;

            serial_print("[AHCI] Controller found PCI 0:");
            serial_print_hex(dev);
            serial_print(".");
            serial_print_hex(fn);
            serial_print("  ABAR=0x");
            serial_print_hex(abar);
            serial_print("\n");

            return abar;
        }
    }
    return 0;
}

/* =========================================================================
 * Public API
 * ========================================================================= */
int ahci_init(void) {
    uint64_t abar = pci_find_ahci_abar();
    if (abar == 0) {
        serial_print("[AHCI] No controller found\n");
        return -1;
    }

    g_abar = (volatile uint8_t *)(uintptr_t)abar;

    /* BIOS/OS Handoff — AHCI 1.3.1 §10.6 */
    if (hba_read(HBA_CAP2) & CAP2_BOH) {
        serial_print("[AHCI] Performing BIOS/OS handoff...\n");
        hba_write(HBA_BOHC, hba_read(HBA_BOHC) | BOHC_OOS);
        for (int i = 0; i < 0x200000; i++) {
            if (!(hba_read(HBA_BOHC) & BOHC_BOS)) break;
        }
        if (hba_read(HBA_BOHC) & BOHC_BB) {
            for (int i = 0; i < 0x800000; i++) {
                if (!(hba_read(HBA_BOHC) & BOHC_BB)) break;
            }
        }
    }

    /* Enable AHCI mode before reset. */
    hba_write(HBA_GHC, hba_read(HBA_GHC) | GHC_AE);

    /* HBA Reset — GHC.HR (bit 0), self-clearing.
     * Source: AHCI 1.3.1 §10.4.3. */
    hba_write(HBA_GHC, hba_read(HBA_GHC) | GHC_HR);

    int reset_ok = 0;
    for (int i = 0; i < 0x100000; i++) {
        if (!(hba_read(HBA_GHC) & GHC_HR)) {
            reset_ok = 1;
            break;
        }
    }

    if (!reset_ok) {
        serial_print("[AHCI] ERROR: HBA reset did not complete (GHC.HR stuck)\n");
        return -1;
    }

    /* Re-enable AHCI mode — HR may clear GHC.AE.
     * Source: AHCI 1.3.1 §10.4.3. */
    hba_write(HBA_GHC, hba_read(HBA_GHC) | GHC_AE);

    serial_print("[AHCI] HBA version=0x");
    serial_print_hex(hba_read(HBA_VS));
    serial_print("  PI=0x");
    serial_print_hex(hba_read(HBA_PI));
    serial_print("\n");

    uint32_t pi = hba_read(HBA_PI);
    for (int p = 0; p < 32; p++) {
        if (!(pi & (1u << p))) continue;

        serial_print("[AHCI] Probing port ");
        serial_print_hex((uint64_t)p);
        serial_print("  SSTS=0x");
        serial_print_hex(port_read(p, PORT_SSTS));
        serial_print("  SIG=0x");
        serial_print_hex(port_read(p, PORT_SIG));
        serial_print("\n");

        if (port_init(p) == 0) {
            g_port = p;
            serial_print("[AHCI] Initialised port ");
            serial_print_hex((uint64_t)p);
            serial_print("\n");
            return 0;
        }
    }

    serial_print("[AHCI] No ATA drive found on any implemented port\n");
    return -1;
}

int ahci_read_sectors(uint64_t lba, uint16_t count, void *buf) {
    if (g_port < 0) {
        serial_print("[AHCI] ERROR: not initialised\n");
        return -1;
    }
    return port_transfer(lba, count, buf, 0);
}

int ahci_write_sectors(uint64_t lba, uint16_t count, const void *buf) {
    if (g_port < 0) {
        serial_print("[AHCI] ERROR: not initialised\n");
        return -1;
    }
    return port_transfer(lba, count, (void *)buf, 1);
}