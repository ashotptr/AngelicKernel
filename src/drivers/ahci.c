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

/* PxSSTS DET and IPM fields — AHCI 1.3.1 §3.3.10 Table 28
 *   DET bits 3:0 — Device Detection and interface comm status
 *   IPM bits 11:8 — Interface Power Management state
 */
#define SSTS_DET_MASK      0x0Fu
#define SSTS_DET_PRESENT   0x03u  /* device present, comm established */
#define SSTS_IPM_MASK      0xF00u
#define SSTS_IPM_ACTIVE    0x100u /* interface in active power state  */

/* PxIS bit 30 — Task File Error Status — AHCI 1.3.1 §3.3.5 Table 18
 * Set by the HBA when PxTFD.ERR is set after a command completes.
 * Software must check this before declaring a transfer successful. */
#define PIS_TFES (1u << 30)

/* =========================================================================
 * AHCI system-memory data structures
 *
 * Source: AHCI 1.3.1 §4 "System Memory Structures"
 * ========================================================================= */

/* Command Header — one of up to 32 slots in the Command List.
 * Each slot is 32 bytes.  Source: AHCI 1.3.1 §4.2.2 Table 12. */
typedef struct {
    /*
     * flags [15:0]:
     *   [4:0]  CFL  — Command FIS Length in DWORDs (must be 2–16; 5 for H2D)
     *   [5]    A    — ATAPI command (0 for ATA)
     *   [6]    W    — Write direction: 1 = H2D (write to device), 0 = D2H
     *   [7]    P    — Prefetchable
     *   [11:8] reserved
     *   [15:12] PMP — Port Multiplier Port (0 — no multiplier)
     */
    uint16_t flags;
    uint16_t prdtl;   /* Physical Region Descriptor Table entry count */
    uint32_t prdbc;   /* PRD Byte Count transferred (written by HBA)  */
    uint32_t ctba;    /* Command Table Base Address (128-byte aligned) */
    uint32_t ctbau;   /* Command Table Base Address Upper 32 bits      */
    uint32_t _res[4]; /* reserved DWORDs 4–7                          */
} __attribute__((packed)) hba_cmd_hdr_t;

_Static_assert(sizeof(hba_cmd_hdr_t) == 32, "hba_cmd_hdr_t must be 32 bytes");

/* Physical Region Descriptor Table entry — AHCI 1.3.1 §4.2.3 Table 18.
 * Each entry describes a contiguous region of physical memory for DMA. */
typedef struct {
    uint32_t dba;   /* Data Base Address (must be word-aligned, bit 0 = 0) */
    uint32_t dbau;  /* Data Base Address Upper 32 bits                      */
    uint32_t _res;
    /*
     * dbc: Byte Count — ZERO-BASED.  A value of 0 means 1 byte transferred.
     * Maximum is 0x3FFFFF (4 MB - 1), meaning 4 MB per PRDT entry.
     * Bit 31 = interrupt-on-completion flag (we leave it 0; we poll).
     * Source: AHCI 1.3.1 §4.2.3 Table 18, DW3 "Byte Count (DBC)".
     */
    uint32_t dbc;
} __attribute__((packed)) hba_prdt_t;

_Static_assert(sizeof(hba_prdt_t) == 16, "hba_prdt_t must be 16 bytes");

/* Command Table — pointed to by the Command Header's CTBA field.
 * Layout: Command FIS (64 B) | ATAPI cmd (16 B) | reserved (48 B) | PRDT[]
 * Source: AHCI 1.3.1 §4.2.3 Figure 13. */
typedef struct {
    uint8_t    cfis[64];   /* Command FIS: filled with a H2D Register FIS   */
    uint8_t    acmd[16];   /* ATAPI command (unused for ATA commands)        */
    uint8_t    _res[48];   /* reserved                                       */
    hba_prdt_t prdt[1];    /* one PRDT entry covers our whole transfer       */
} __attribute__((packed)) hba_cmd_tbl_t;

/* H2D Register FIS — Register Host-to-Device Frame Information Structure.
 * This is the command FIS written into cfis[] to issue an ATA command.
 * Source: Serial ATA Revision 3.0 §10.3.1 "Register - Host to Device FIS"
 *         also summarised in AHCI 1.3.1 §4.2.3. */
typedef struct {
    uint8_t  fis_type;  /* 0x27 — FIS_TYPE_REG_H2D                          */
    uint8_t  flags;     /* bit 7 = C (1 = command register update);
                         * bits 3:0 = Port Multiplier Port (0)               */
    uint8_t  command;   /* ATA command opcode (e.g. 0x25 = READ DMA EXT)     */
    uint8_t  featurel;  /* Feature register, bits 7:0 (command-specific)     */

    uint8_t  lba0;      /* LBA bits  7: 0                                    */
    uint8_t  lba1;      /* LBA bits 15: 8                                    */
    uint8_t  lba2;      /* LBA bits 23:16                                    */
    uint8_t  device;    /* Device register:
                         *   bit 6 = 1 → LBA mode (vs CHS)
                         *   bit 4 = device select (0 = device 0 / master)
                         * Source: ATA8-ACS §7.2.1 Table 12                  */

    uint8_t  lba3;      /* LBA bits 31:24                                    */
    uint8_t  lba4;      /* LBA bits 39:32                                    */
    uint8_t  lba5;      /* LBA bits 47:40                                    */
    uint8_t  featureh;  /* Feature register, bits 15:8                       */

    uint8_t  countl;    /* Sector count, bits  7:0                           */
    uint8_t  counth;    /* Sector count, bits 15:8                           */
    uint8_t  icc;       /* Isochronous Command Completion (0 = not used)     */
    uint8_t  control;   /* Device Control register (0 = no reset, no IRQ)   */

    uint8_t  _res[4];   /* reserved DW4                                      */
} __attribute__((packed)) fis_h2d_t;

_Static_assert(sizeof(fis_h2d_t) == 20, "fis_h2d_t must be 20 bytes");

/* FIS type byte for a H2D Register FIS.
 * Source: Serial ATA Revision 3.0 §10.3 Table 111. */
#define FIS_TYPE_H2D   0x27u

/* C bit in fis_h2d_t.flags: set to 1 to indicate this FIS carries a new
 * command register value (as opposed to a device-control update).
 * Source: Serial ATA Revision 3.0 §10.3.1. */
#define FIS_FLAG_CMD   0x80u

/* ATA command opcodes used by this driver.
 * Source: ATA8-ACS (INCITS 452-2009)
 *   0x25 — READ DMA EXT    §7.25  (48-bit LBA DMA read)
 *   0x35 — WRITE DMA EXT   §7.56  (48-bit LBA DMA write)
 *   0xEA — FLUSH CACHE EXT §7.13  (flush volatile write cache, 48-bit form)
 *   0xEC — IDENTIFY DEVICE §7.16  (return 512-byte drive identity block)
 */
#define ATA_READ_DMA_EXT   0x25u
#define ATA_WRITE_DMA_EXT  0x35u
#define ATA_FLUSH_EXT      0xEAu
#define ATA_IDENTIFY       0xECu

/* =========================================================================
 * Static DMA-capable memory structures
 *
 * These must be reachable by the HBA's DMA engine.  Under an identity-mapped
 * page table, virtual address == physical address, so the C pointer is the
 * bus address the HBA should use.  If the VMM uses a non-identity mapping,
 * translate through vmm_virt_to_phys() before writing PORT_CLB/FB/CTBA.
 *
 * Alignment requirements from AHCI 1.3.1:
 *   §3.3.1  PxCLB  — Command List Base must be 1 KB aligned
 *   §3.3.3  PxFB   — FIS Base must be 256 B aligned
 *   §4.2.3  CTBA   — Command Table must be 128 B aligned
 * ========================================================================= */

/* Command list: 32 slots × 32 B = 1 024 B.  Must be 1 KB aligned. */
static hba_cmd_hdr_t s_cmd_list[32] __attribute__((aligned(1024)));

/* Received FIS area: 256 B.  Must be 256 B aligned. */
static uint8_t s_fis_area[256]      __attribute__((aligned(256)));

/* Command table with 1 embedded PRDT entry.  Must be 128 B aligned. */
static hba_cmd_tbl_t s_cmd_tbl      __attribute__((aligned(128)));

/*
 * DMA data buffer — 128 sectors × 512 B = 64 KB.
 * 128 sectors covers our largest single persist call (56 sectors for the
 * roster store).  Page-aligned (4 KB) so the physical address is unambiguous
 * when writing the PRDT DBA field.
 */
#define AHCI_DMA_SECTORS 128u
static uint8_t s_dma_buf[AHCI_DMA_SECTORS * 512] __attribute__((aligned(4096)));

/* =========================================================================
 * Driver state
 * ========================================================================= */

/* Base address of the HBA's MMIO register space (ABAR = BAR5).
 * Declared volatile because every read/write is a hardware register access. */
static volatile uint8_t *g_abar = NULL;

/* Which port index is in use (-1 = not initialised) */
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
    /*
     * Per-port registers start at ABAR + 0x100 and each port occupies
     * 0x80 (128) bytes.  Source: AHCI 1.3.1 §3.3, Table 7.
     */
    return hba_read(0x100u + (uint32_t)p * 0x80u + off);
}

static inline void port_write(int p, uint32_t off, uint32_t val) {
    hba_write(0x100u + (uint32_t)p * 0x80u + off, val);
}

/* =========================================================================
 * Port DMA engine start / stop
 *
 * The correct stop sequence per AHCI 1.3.1 §10.3.1:
 *   1. Clear PxCMD.ST and wait for PxCMD.CR to clear.
 *   2. Clear PxCMD.FRE and wait for PxCMD.FR to clear.
 *
 * The correct start sequence per AHCI 1.3.1 §10.3.1:
 *   1. Wait for PxCMD.CR to be clear (it must not be set before ST is set).
 *   2. Set PxCMD.FRE.
 *   3. Set PxCMD.ST.
 * ========================================================================= */

static void port_stop_engine(int p) {
    /* Step 1 — clear ST (stop DMA engine) */
    port_write(p, PORT_CMD, port_read(p, PORT_CMD) & ~PCMD_ST);

    /* Wait for CR (Command List Running) to clear — AHCI §10.3.1 */
    for (int i = 0; i < 500000; i++) {
        if (!(port_read(p, PORT_CMD) & PCMD_CR)) {
            break;
        }
    }

    /* Step 2 — clear FRE (stop FIS receive engine) */
    port_write(p, PORT_CMD, port_read(p, PORT_CMD) & ~PCMD_FRE);

    /* Wait for FR (FIS Receive Running) to clear — AHCI §10.3.2 */
    for (int i = 0; i < 500000; i++) {
        if (!(port_read(p, PORT_CMD) & PCMD_FR)){
            break;
        }
    }
}

static void port_start_engine(int p) {
    /* Must ensure CR is clear before asserting ST — AHCI §10.3.1 */
    for (int i = 0; i < 500000; i++) {
        if (!(port_read(p, PORT_CMD) & PCMD_CR)){
            break;
        }
    }

    /* Set FRE first, then ST */
    port_write(p, PORT_CMD, port_read(p, PORT_CMD) | PCMD_FRE);
    port_write(p, PORT_CMD, port_read(p, PORT_CMD) | PCMD_ST);
}

/* =========================================================================
 * Port initialisation
 *
 * Returns 0 if a drive is present and the port is ready, -1 otherwise.
 * ========================================================================= */

static int port_init(int p) {
    /* Check PxSSTS: device present (DET=3) and interface active (IPM=1).
     * DET=3 means "device detected and Phy communication established".
     * Source: AHCI 1.3.1 §3.3.10 Table 28 (PxSSTS SStatus). */
    uint32_t ssts = port_read(p, PORT_SSTS);

    if ((ssts & SSTS_DET_MASK) != SSTS_DET_PRESENT) {
        return -1;
    }

    if ((ssts & SSTS_IPM_MASK) != SSTS_IPM_ACTIVE) {
        return -1;
    }

    port_stop_engine(p);

    /* Point CLB and FB at our static structures.
     * Both the 32-bit and upper-32-bit registers must be written even when
     * operating in 32-bit physical address space (upper = 0). */
    uint64_t clb_phys = (uint64_t)(uintptr_t)s_cmd_list;
    uint64_t fb_phys = (uint64_t)(uintptr_t)s_fis_area;

    port_write(p, PORT_CLB, (uint32_t)(clb_phys & 0xFFFFFFFFu));
    port_write(p, PORT_CLBU, (uint32_t)(clb_phys >> 32));
    port_write(p, PORT_FB, (uint32_t)(fb_phys & 0xFFFFFFFFu));
    port_write(p, PORT_FBU, (uint32_t)(fb_phys >> 32));

    /* Zero all DMA structures after writing the port registers.
     * The HBA may start using them as soon as FRE is set. */
    memset(s_cmd_list, 0, sizeof(s_cmd_list));
    memset(s_fis_area, 0, sizeof(s_fis_area));
    memset(&s_cmd_tbl, 0, sizeof(s_cmd_tbl));

    /* Wire command slot 0 to our single command table.
     * CTBA must be 128-byte aligned — AHCI 1.3.1 §4.2.3. */
    uint64_t ctba_phys = (uint64_t)(uintptr_t)&s_cmd_tbl;
    s_cmd_list[0].ctba = (uint32_t)(ctba_phys & 0xFFFFFFFFu);
    s_cmd_list[0].ctbau = (uint32_t)(ctba_phys >> 32);

    /* Clear any sticky error and interrupt bits that may be left over
     * from BIOS activity.  Writing 1s to IS and SERR clears them.
     * Source: AHCI 1.3.1 §3.3.5 (PxIS) and §3.3.12 (PxSERR). */
    port_write(p, PORT_SERR, 0xFFFFFFFFu);
    port_write(p, PORT_IS, 0xFFFFFFFFu);

    /* Staggered spin-up: if CAP.SSS (bit 2) is set, the firmware may have
     * left the drive spun down to allow staggered power-on across ports.
     * Assert SUD (Spin-Up Device) and POD (Power On Device) to wake it.
     * Source: AHCI 1.3.1 §3.1.1 Table 4 (CAP.SSS), §10.10 "Staggered
     *         Spin-up Operation", §3.3.7 Table 23 (PxCMD.SUD / PxCMD.POD). */
    uint32_t caps = hba_read(HBA_CAP);

    if (caps & (1u << 2)) {
        uint32_t pcmd = port_read(p, PORT_CMD);

        port_write(p, PORT_CMD, pcmd | PCMD_SUD | PCMD_POD);
    }

    /* COMRESET: set PxSCTL.DET=1 to initiate interface communication
     * initialisation (a COMRESET on the PHY link), then clear to DET=0.
     *
     * PxSCTL.DET field (bits 3:0) — AHCI 1.3.1 §3.3.11 Table 30:
     *   0 = no OOB is performed
     *   1 = perform interface communication initialisation (COMRESET)
     *   4 = disable PHY (port goes offline)
     *
     * The COMRESET must be held for at least 1 ms per AHCI §10.4.2.
     * We have no timer, so we spin.  On real hardware an I/O read via
     * MMIO takes roughly 50–200 ns depending on bus latency; 20 000
     * iterations is therefore a conservative lower bound (~1–4 ms).
     * On QEMU under TCG the loop is much faster but the emulated SATA
     * link resets instantly so timing does not matter there.
     * Source: AHCI 1.3.1 §10.4.2 "Port Reset". */
    uint32_t sctl = port_read(p, PORT_SCTL);

    port_write(p, PORT_SCTL, (sctl & ~0xFu) | 0x1u); /* DET=1 → COMRESET */

    for (volatile int i = 0; i < 20000; i++){          /* ≥1 ms hold        */
        (void)port_read(p, PORT_SCTL);
    }

    port_write(p, PORT_SCTL, sctl & ~0xFu);           /* DET=0 → release   */

    /* After COMRESET, wait for DET=3 again — the PHY needs time to
     * re-negotiate the link.  Source: AHCI 1.3.1 §10.4.2. */
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

    port_start_engine(p);

    /* Wait for TFD to show BSY=0 and DRQ=0 — drive is ready for commands.
     * Source: AHCI 1.3.1 §10.3.1 (start command engine procedure). */
    for (int i = 0; i < 0x100000; i++) {
        uint32_t tfd = port_read(p, PORT_TFD);

        if (!(tfd & (TFD_BSY | TFD_DRQ))) {
            break;
        }
    }

    return 0;
}

/* =========================================================================
 * Issue a command in slot 0 and poll for completion
 * ========================================================================= */

static int port_wait_slot0(void) {
    /*
     * Poll PxIS.TFES (bit 30) first: if set, the HBA detected a task-file
     * error (drive set ERR in the status byte).  Source: AHCI 1.3.1 §3.3.5.
     *
     * Then poll PxCI bit 0: cleared by the HBA when the command in slot 0
     * completes successfully.  Source: AHCI 1.3.1 §3.3.14.
     */
    for (uint32_t i = 0; i < 0x2000000u; i++) {
        if (port_read(g_port, PORT_IS) & PIS_TFES) {
            serial_print("[AHCI] ERROR: Task File Error (TFD=0x");
            serial_print_hex(port_read(g_port, PORT_TFD));
            serial_print(")\n");

            return -1;
        }

        if (!(port_read(g_port, PORT_CI) & 1u)) {
            return 0;
        }
    }

    serial_print("[AHCI] ERROR: command timeout\n");

    return -1;
}

/* Core transfer: read or write 'count' sectors at 48-bit LBA.
 * Data moves through the static s_dma_buf to avoid alignment and overlap
 * issues with caller-supplied buffers. */
static int port_transfer(uint64_t lba, uint16_t count, void *buf, int write) {
    if (count == 0 || count > AHCI_DMA_SECTORS) {
        serial_print("[AHCI] ERROR: count out of range\n");

        return -1;
    }

    /* Wait for the port to be idle (no pending BSY or DRQ) before
     * submitting a new command.  Source: AHCI 1.3.1 §5.5.1. */
    for (int i = 0; i < 0x100000; i++) {
        if (!(port_read(g_port, PORT_TFD) & (TFD_BSY | TFD_DRQ))) {
            break;
        }
    }

    uint32_t byte_count = (uint32_t)count * 512u;

    if (write) {
        memcpy(s_dma_buf, buf, byte_count);
    }

    /* ----- Build the Command Table ----- */
    memset(&s_cmd_tbl, 0, sizeof(s_cmd_tbl));

    /* Fill in the H2D Register FIS in cfis[].
     * The FIS must be 20 bytes (5 DWORDs); unused bytes must be zero. */
    fis_h2d_t *fis = (fis_h2d_t *)s_cmd_tbl.cfis;
    fis->fis_type = FIS_TYPE_H2D;
    fis->flags = FIS_FLAG_CMD;   /* C=1: this is a command update */
    fis->command = write ? ATA_WRITE_DMA_EXT : ATA_READ_DMA_EXT;

    /*
     * Device register for LBA48 DMA commands:
     *   bit 6 = 1 → LBA mode (mandatory for LBA48)
     *   bit 4 = 0 → device 0 (master); with AHCI, port selection handles
     *               physical device routing, so this is always 0.
     * Source: ATA8-ACS §7.2.1 Table 12; AHCI 1.3.1 §4.2.3.
     */
    fis->device = (1u << 6);

    /* 48-bit LBA split across lba0–lba5.
     * Source: ATA8-ACS §7.25 (READ DMA EXT register description). */
    fis->lba0 = (uint8_t)(lba & 0xFFu);
    fis->lba1 = (uint8_t)((lba >>  8) & 0xFFu);
    fis->lba2 = (uint8_t)((lba >> 16) & 0xFFu);
    fis->lba3 = (uint8_t)((lba >> 24) & 0xFFu);
    fis->lba4 = (uint8_t)((lba >> 32) & 0xFFu);
    fis->lba5 = (uint8_t)((lba >> 40) & 0xFFu);

    /* Sector count split across countl (bits 7:0) and counth (bits 15:8).
     * A count of 0 means 65 536 sectors (not used here). */
    fis->countl = (uint8_t)(count & 0xFFu);
    fis->counth = (uint8_t)((count >> 8) & 0xFFu);

    /* ----- Single PRDT entry pointing at s_dma_buf ----- */
    uint64_t dba_phys = (uint64_t)(uintptr_t)s_dma_buf;
    s_cmd_tbl.prdt[0].dba = (uint32_t)(dba_phys & 0xFFFFFFFFu);
    s_cmd_tbl.prdt[0].dbau = (uint32_t)(dba_phys >> 32);
    /*
     * dbc is ZERO-BASED: set to (byte_count - 1).
     * A value of 0 means 1 byte.  Source: AHCI 1.3.1 §4.2.3 Table 18.
     */
    s_cmd_tbl.prdt[0].dbc = byte_count - 1u;

    /* ----- Build the Command Header for slot 0 ----- */
    /*
     * flags field layout (AHCI 1.3.1 §4.2.2 Table 12):
     *   [4:0] CFL  = 5 — Command FIS Length in DWORDs.
     *                    sizeof(fis_h2d_t) = 20 bytes = 5 × 4-byte DWORDs.
     *   [5]   A    = 0 — Not ATAPI
     *   [6]   W    = write ? 1 : 0 — Write bit: 1 = host→device data flow
     *   [7]   P    = 0 — Not prefetchable
     *   [15:12] PMP = 0 — No port multiplier
     */
    s_cmd_list[0].flags = (uint16_t)(5u | (write ? (1u << 6) : 0u));
    s_cmd_list[0].prdtl = 1u;   /* one PRDT entry */
    s_cmd_list[0].prdbc = 0u;   /* HBA writes actual byte count here on completion */

    /* ----- Issue the command and wait for completion ----- */
    port_write(g_port, PORT_IS, 0xFFFFFFFFu); /* clear pending interrupt bits */
    port_write(g_port, PORT_SERR, 0xFFFFFFFFu); /* clear SATA error register    */

    /*
     * Setting bit 0 of PxCI issues slot 0.  The HBA starts DMA immediately.
     * Source: AHCI 1.3.1 §3.3.14 PxCI.
     */
    port_write(g_port, PORT_CI, 1u);

    if (port_wait_slot0() != 0) {
        return -1;
    }

    if (!write) {
        memcpy(buf, s_dma_buf, byte_count);
    }

    return 0;
}

/* =========================================================================
 * Public API
 * ========================================================================= */

/*
 * pci_find_ahci_abar
 *
 * Scans PCI bus 0 for an AHCI controller by class/subclass/prog-if:
 *   Class    = 0x01 (Mass Storage Controller)
 *   Subclass = 0x06 (Serial ATA)
 *   Prog-IF  = 0x01 (AHCI 1.0)
 *
 * Source: PCI-to-PCI Bridge Architecture Specification and the PCI Code and
 *         ID Assignment Specification Revision 1.7, §D (Mass Storage, 01h).
 *         AHCI 1.3.1 §2.1.5 specifies the AHCI Prog-IF value as 01h.
 *
 * When found:
 *   - Enables Memory Space (bit 1) and Bus Master (bit 2) in the PCI
 *     Command register (offset 0x04).  Both are required for MMIO access
 *     and DMA.  Source: PCI Local Bus Spec §6.2.2; AHCI checklist §9.1.
 *
 *   - Returns the 32-bit base address from BAR5 (offset 0x24), which is
 *     the AHCI Base Address Register (ABAR).
 *     BAR attribute bits 3:0 are masked off:
 *       bit 0   = 0  (memory space indicator, always 0 for memory BARs)
 *       bits 2:1 = BAR type (00=32-bit, 10=64-bit, 01/11=reserved)
 *       bit 3   = prefetchable flag
 *     Source: PCI Local Bus Spec §6.2.5.1 "Base Address Registers".
 *
 * NOTE: We assume BAR5 is a 32-bit memory BAR (bits 2:1 = 0b00).  This is
 * guaranteed by the AHCI specification §2.1.11 which mandates that ABAR is
 * a non-prefetchable 32-bit memory BAR.  A 64-bit BAR would require reading
 * the upper 32 bits from offset 0x28 as well.
 *
 * Returns the ABAR physical address, or 0 if no controller is found.
 */
static uint64_t pci_find_ahci_abar(void) {
    for (uint8_t dev = 0; dev < 32; dev++) {
        for (uint8_t fn = 0; fn < 8; fn++) {
            uint32_t id = pci_read32(0, dev, fn, 0x00);

            /* Vendor ID 0xFFFF means no device at this slot (floating bus).
             * Source: PCI Local Bus Spec §6.1. */
            if ((id & 0xFFFF) == 0xFFFFu) {
                /* If function 0 is absent the whole slot is empty — no need
                 * to probe functions 1–7 on this device. */
                if (fn == 0) {
                    break;
                }

                continue;
            }

            /* PCI Configuration offset 0x08 layout:
             *   bits 31:24 = Class Code
             *   bits 23:16 = Subclass Code
             *   bits 15:8  = Prog-IF
             *   bits  7:0  = Revision ID
             * Source: PCI Local Bus Spec §6.2.1. */
            uint32_t cc = pci_read32(0, dev, fn, 0x08);
            int is_ahci = ((cc >> 24) & 0xFF) == 0x01u   /* Mass Storage  */
                       && ((cc >> 16) & 0xFF) == 0x06u   /* Serial ATA    */
                       && ((cc >>  8) & 0xFF) == 0x01u;  /* AHCI 1.0      */

            if (!is_ahci) {
                /*
                 * Multi-function check: PCI Configuration offset 0x0C bits
                 * 23:16 = Header Type.  Bit 7 of Header Type = multi-function
                 * device.  If not set on function 0, functions 1–7 don't
                 * exist on this slot.  Source: PCI Local Bus Spec §6.2.
                 */
                if (fn == 0) {
                    uint32_t ht = pci_read32(0, dev, 0, 0x0C);

                    if (!((ht >> 16) & 0x80u)){
                        break;
                    }
                }

                continue;
            }

            /* Enable Memory Space (bit 1) + Bus Master (bit 2).
             * Source: PCI Local Bus Spec §6.2.2 Command Register. */
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

int ahci_init(void) {
    uint64_t abar = pci_find_ahci_abar();

    if (abar == 0) {
        serial_print("[AHCI] No controller found\n");

        return -1;
    }

    g_abar = (volatile uint8_t *)(uintptr_t)abar;

    /* -----------------------------------------------------------------
     * BIOS/OS Handoff — AHCI 1.3.1 §10.6
     *
     * If CAP2.BOH (bit 0) is set the controller supports the handoff
     * mechanism.  The sequence is:
     *   1. Set BOHC.OOS (OS-Owned Semaphore, bit 1).
     *   2. Wait for BOHC.BOS (BIOS-Owned Semaphore, bit 0) to clear —
     *      BIOS acknowledges by releasing ownership.
     *   3. If BOHC.BB (BIOS Busy, bit 4) is set, wait for it to clear
     *      (BIOS is finishing cleanup; spec allows up to 2 seconds).
     * Source: AHCI 1.3.1 §10.6.3 "OS declares ownership request".
     * ----------------------------------------------------------------- */
    if (hba_read(HBA_CAP2) & CAP2_BOH) {
        serial_print("[AHCI] Performing BIOS/OS handoff...\n");

        hba_write(HBA_BOHC, hba_read(HBA_BOHC) | BOHC_OOS);

        /* Wait for BOS to clear */
        for (int i = 0; i < 0x200000; i++) {
            if (!(hba_read(HBA_BOHC) & BOHC_BOS)) {
                break;
            }
        }

        /* Only wait for BB if the BIOS set it (BIOS is still busy). */
        if (hba_read(HBA_BOHC) & BOHC_BB) {
            for (int i = 0; i < 0x800000; i++) {
                if (!(hba_read(HBA_BOHC) & BOHC_BB)) {
                    break;
                }
            }
        }
    }

    /* -----------------------------------------------------------------
     * Enable AHCI mode before reset.
     * GHC.AE (bit 31) must be set to access AHCI registers.  Software
     * should set this before accessing any port registers.
     * Source: AHCI 1.3.1 §10.1.2 step 1.
     * ----------------------------------------------------------------- */
    hba_write(HBA_GHC, hba_read(HBA_GHC) | GHC_AE);

    /* -----------------------------------------------------------------
     * HBA Reset — GHC.HR (bit 0).
     * Setting this bit resets all HBA state including port registers.
     * The bit self-clears when reset is complete (hardware guarantee).
     * Software must poll until it clears.
     * Source: AHCI 1.3.1 §10.4.3 "HBA Reset".
     * ----------------------------------------------------------------- */
    hba_write(HBA_GHC, hba_read(HBA_GHC) | GHC_HR);

    for (int i = 0; i < 0x100000; i++) {
        if (!(hba_read(HBA_GHC) & GHC_HR)) {
            break;
        }    }

    /* Re-enable AHCI mode after reset — HR clears GHC.AE.
     * Source: AHCI 1.3.1 §10.4.3 "After a reset, GHC.AE may be cleared." */
    hba_write(HBA_GHC, hba_read(HBA_GHC) | GHC_AE);

    serial_print("[AHCI] HBA version=0x");
    serial_print_hex(hba_read(HBA_VS));
    serial_print("  PI=0x");
    serial_print_hex(hba_read(HBA_PI));
    serial_print("\n");

    /* -----------------------------------------------------------------
     * Find the first implemented port that has a drive attached.
     * HBA_PI is a bitmask: bit N set → port N is implemented.
     * Source: AHCI 1.3.1 §3.1.4 "Ports Implemented".
     * ----------------------------------------------------------------- */
    uint32_t pi = hba_read(HBA_PI);

    for (int p = 0; p < 32; p++) {
        if (!(pi & (1u << p))) {
            continue;
        }

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

    serial_print("[AHCI] No drive found on any implemented port\n");

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