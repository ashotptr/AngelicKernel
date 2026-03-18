/* ===========================================================================
 * ahci.c — AHCI (Serial ATA) host controller driver
 *
 * Supports a single data drive (the first port with a connected device).
 * Uses command slot 0 only (no NCQ, no port multipliers — KISS).
 * All DMA structures are static and identity-mapped.
 * =========================================================================== */

#include "drivers/ahci.h"
#include <stdint.h>
#include <string.h>

extern void serial_print(const char *s);
extern void serial_print_hex(uint64_t n);

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
    uint32_t addr = (1u << 31) | ((uint32_t)bus << 16) | ((uint32_t)dev << 11) | ((uint32_t)fn  <<  8) | (off & 0xFCu);
    
    outl_pio(PCI_CONFIG_ADDR, addr);
    
    return inl_pio(PCI_CONFIG_DATA);
}

static void pci_write32(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off, uint32_t val) {
    uint32_t addr = (1u << 31) | ((uint32_t)bus << 16) | ((uint32_t)dev << 11) | ((uint32_t)fn  <<  8) | (off & 0xFCu);

    outl_pio(PCI_CONFIG_ADDR, addr);

    outl_pio(PCI_CONFIG_DATA, val);
}

/* =========================================================================
 * AHCI HBA register layout (MMIO, relative to ABAR)
 * ========================================================================= */

/* Generic Host Control registers */
#define HBA_CAP   0x00u   /* Host Capabilities */
#define HBA_GHC   0x04u   /* Global Host Control */
#define HBA_IS    0x08u   /* Interrupt Status */
#define HBA_PI    0x0Cu   /* Ports Implemented bitmask */
#define HBA_VS    0x10u   /* Version */
#define HBA_CAP2  0x24u   /* Host Capabilities Extended */
#define HBA_BOHC  0x28u   /* BIOS/OS Handoff Control */

#define GHC_AE    (1u << 31)  /* AHCI Enable */
#define GHC_IE    (1u <<  1)  /* Interrupt Enable (keep 0 — polling) */
#define GHC_HR    (1u <<  0)  /* HBA Reset */

#define CAP2_BOH  (1u <<  0)  /* Supports BIOS/OS Handoff */
#define BOHC_BOS  (1u <<  0)  /* BIOS-Owned Semaphore */
#define BOHC_OOS  (1u <<  1)  /* OS-Owned Semaphore */
#define BOHC_BB   (1u <<  4)  /* BIOS Busy */

/* Per-port registers (base = ABAR + 0x100 + port * 0x80) */
#define PORT_CLB   0x00u  /* Command List Base (1 KB aligned) */
#define PORT_CLBU  0x04u  /* Command List Base Upper 32 bits */
#define PORT_FB    0x08u  /* FIS Base (256 B aligned) */
#define PORT_FBU   0x0Cu  /* FIS Base Upper 32 bits */
#define PORT_IS    0x10u  /* Interrupt Status */
#define PORT_IE    0x14u  /* Interrupt Enable */
#define PORT_CMD   0x18u  /* Command and Status */
#define PORT_TFD   0x20u  /* Task File Data */
#define PORT_SIG   0x24u  /* Signature */
#define PORT_SSTS  0x28u  /* SATA Status (SCR0: SStatus) */
#define PORT_SCTL  0x2Cu  /* SATA Control (SCR2: SControl) */
#define PORT_SERR  0x30u  /* SATA Error (SCR1: SError) */
#define PORT_SACT  0x34u  /* SATA Active */
#define PORT_CI    0x38u  /* Command Issue */

/* PORT_CMD bits */
#define PCMD_ST   (1u <<  0)  /* Start (DMA engine running) */
#define PCMD_SUD  (1u <<  1)  /* Spin-Up Device */
#define PCMD_POD  (1u <<  2)  /* Power On Device */
#define PCMD_FRE  (1u <<  4)  /* FIS Receive Enable */
#define PCMD_FR   (1u << 14)  /* FIS Receive Running (status) */
#define PCMD_CR   (1u << 15)  /* Command List Running (status) */
#define PCMD_ICC_ACTIVE (0x1u << 28) /* Interface Communication Control */

/* PORT_TFD bits */
#define TFD_ERR  0x01u
#define TFD_DRQ  0x08u
#define TFD_BSY  0x80u

/* PORT_SSTS: DET and IPM fields */
#define SSTS_DET_MASK      0x0Fu
#define SSTS_DET_PRESENT   0x03u  /* device present, comm established */
#define SSTS_IPM_MASK      0xF00u
#define SSTS_IPM_ACTIVE    0x100u /* interface active */

/* PORT_IS bits */
#define PIS_TFES (1u << 30)  /* Task File Error Status */

/* =========================================================================
 * AHCI data structures
 * ========================================================================= */

/* Command Header — one of 32 slots in the command list (32 bytes each) */
typedef struct {
    uint16_t flags;    /* [4:0] CFL, [5] A, [6] W, [7] P … [15:12] PMP */
    uint16_t prdtl;   /* PRD table length (number of entries) */
    uint32_t prdbc;   /* PRD byte count transferred (filled by HBA) */
    uint32_t ctba;    /* Command Table Base Address (128-byte aligned) */
    uint32_t ctbau;   /* Command Table Base Address Upper 32 bits */
    uint32_t _res[4];
} __attribute__((packed)) hba_cmd_hdr_t;

_Static_assert(sizeof(hba_cmd_hdr_t) == 32, "hba_cmd_hdr_t must be 32 bytes");

/* Physical Region Descriptor Table entry (16 bytes) */
typedef struct {
    uint32_t dba;    /* Data Base Address (word-aligned) */
    uint32_t dbau;   /* Data Base Address Upper 32 bits */
    uint32_t _res;
    uint32_t dbc;    /* Byte count minus 1; bit 31 = interrupt on completion */
} __attribute__((packed)) hba_prdt_t;

_Static_assert(sizeof(hba_prdt_t) == 16, "hba_prdt_t must be 16 bytes");

/*
 * Command Table — pointed to by the Command Header.
 * Layout: CFIS (64 B) | ATAPI cmd (16 B) | reserved (48 B) | PRDT[n]
 * We use exactly 1 PRDT entry (max 4 MB per entry, far more than we need).
 */
typedef struct {
    uint8_t   cfis[64];   /* Command FIS */
    uint8_t   acmd[16];   /* ATAPI command (unused) */
    uint8_t   _res[48];
    hba_prdt_t prdt[1];   /* single PRD covers our whole transfer */
} __attribute__((packed)) hba_cmd_tbl_t;

/* H2D Register FIS — the 20-byte command FIS written into cfis[] */
typedef struct {
    uint8_t  fis_type;   /* 0x27 — Register – Host to Device */
    uint8_t  flags;      /* bit 7 = C (1 = command); bits 3:0 = PMP */
    uint8_t  command;    /* ATA command opcode */
    uint8_t  featurel;

    uint8_t  lba0;       /* LBA bits  7: 0 */
    uint8_t  lba1;       /* LBA bits 15: 8 */
    uint8_t  lba2;       /* LBA bits 23:16 */
    uint8_t  device;     /* bit 6 = LBA mode */

    uint8_t  lba3;       /* LBA bits 31:24 */
    uint8_t  lba4;       /* LBA bits 39:32 */
    uint8_t  lba5;       /* LBA bits 47:40 */
    uint8_t  featureh;

    uint8_t  countl;     /* sector count bits  7:0 */
    uint8_t  counth;     /* sector count bits 15:8 */
    uint8_t  icc;
    uint8_t  control;

    uint8_t  _res[4];
} __attribute__((packed)) fis_h2d_t;

_Static_assert(sizeof(fis_h2d_t) == 20, "fis_h2d_t must be 20 bytes");

#define FIS_TYPE_H2D   0x27u
#define FIS_FLAG_CMD   0x80u   /* C bit: this is a command, not a control FIS */

/* ATA commands used */
#define ATA_READ_DMA_EXT   0x25u
#define ATA_WRITE_DMA_EXT  0x35u
#define ATA_FLUSH_EXT      0xEAu
#define ATA_IDENTIFY       0xECu

/* =========================================================================
 * Static DMA-capable structures
 *
 * These must be reachable by the HBA's DMA engine.  Under an identity-
 * mapped page table, virtual == physical, so the C address is the bus
 * address.  If the VMM uses a non-identity mapping, translate through
 * vmm_virt_to_phys() before writing the CLB/FB/CTBA registers.
 * ========================================================================= */

/* Command list: 32 headers × 32 B = 1 KB.  Must be 1 KB aligned. */
static hba_cmd_hdr_t s_cmd_list[32] __attribute__((aligned(1024)));

/* Received FIS area: 256 B.  Must be 256 B aligned. */
static uint8_t s_fis_area[256]      __attribute__((aligned(256)));

/* Command table (with embedded PRDT[1]).  Must be 128 B aligned. */
static hba_cmd_tbl_t s_cmd_tbl      __attribute__((aligned(128)));

/*
 * DMA data buffer — 128 sectors × 512 B = 64 KB.
 * Covers our largest single persist call (56 sectors for the roster store).
 * Page-aligned so the physical address is unambiguous.
 */
#define AHCI_DMA_SECTORS 128u
static uint8_t s_dma_buf[AHCI_DMA_SECTORS * 512] __attribute__((aligned(4096)));

/* =========================================================================
 * Driver state
 * ========================================================================= */

/* Base address of the HBA's MMIO register space (ABAR) */
static volatile uint8_t *g_abar = NULL;

/* Which port index we're using */
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
 * Port engine start / stop
 * ========================================================================= */

static void port_stop_engine(int p) {
    /* Clear ST (stop DMA engine) */
    port_write(p, PORT_CMD, port_read(p, PORT_CMD) & ~PCMD_ST);

    for (int i = 0; i < 500000; i++) {
        if (!(port_read(p, PORT_CMD) & PCMD_CR)) {
            break;
        }
    }

    /* Clear FRE (stop FIS receive) */
    port_write(p, PORT_CMD, port_read(p, PORT_CMD) & ~PCMD_FRE);

    for (int i = 0; i < 500000; i++) {
        if (!(port_read(p, PORT_CMD) & PCMD_FR)) {
            break;
        }
    }
}

static void port_start_engine(int p) {
    /* Must wait for CR to clear before asserting ST */
    for (int i = 0; i < 500000; i++) {
        if (!(port_read(p, PORT_CMD) & PCMD_CR)) {
            break;
        }
    }

    port_write(p, PORT_CMD, port_read(p, PORT_CMD) | PCMD_FRE);
    port_write(p, PORT_CMD, port_read(p, PORT_CMD) | PCMD_ST);
}

/* =========================================================================
 * Port initialisation
 *
 * Returns 0 if a drive is present and the port is ready, -1 otherwise.
 * ========================================================================= */

static int port_init(int p) {
    /* Check SATA Status: device present (DET=3) and interface active (IPM=1) */
    uint32_t ssts = port_read(p, PORT_SSTS);
    
    if ((ssts & SSTS_DET_MASK) != SSTS_DET_PRESENT) {
        return -1;
    }

    if ((ssts & SSTS_IPM_MASK) != SSTS_IPM_ACTIVE) {
        return -1;
    }

    port_stop_engine(p);

    /* Point CLB → our static command list, FB → our static FIS area */
    uint64_t clb_phys = (uint64_t)s_cmd_list;
    uint64_t fb_phys = (uint64_t)s_fis_area;

    port_write(p, PORT_CLB, (uint32_t)(clb_phys & 0xFFFFFFFFu));
    port_write(p, PORT_CLBU, (uint32_t)(clb_phys >> 32));
    port_write(p, PORT_FB, (uint32_t)(fb_phys & 0xFFFFFFFFu));
    port_write(p, PORT_FBU, (uint32_t)(fb_phys >> 32));

    /* Zero structures */
    memset(s_cmd_list, 0, sizeof(s_cmd_list));
    memset(s_fis_area, 0, sizeof(s_fis_area));
    memset(&s_cmd_tbl, 0, sizeof(s_cmd_tbl));

    /* Wire command header 0 → our single command table */
    uint64_t ctba_phys = (uint64_t)&s_cmd_tbl;
    s_cmd_list[0].ctba = (uint32_t)(ctba_phys & 0xFFFFFFFFu);
    s_cmd_list[0].ctbau = (uint32_t)(ctba_phys >> 32);

    /* Clear sticky error and interrupt bits */
    port_write(p, PORT_SERR, 0xFFFFFFFFu);
    port_write(p, PORT_IS, 0xFFFFFFFFu);

    /* Spin-up and power-on if the port supports it */
    uint32_t caps = hba_read(HBA_CAP);
    
    if (caps & (1u << 2)) {  /* CAP.SSS — staggered spin-up */
        uint32_t pcmd = port_read(p, PORT_CMD);
        
        port_write(p, PORT_CMD, pcmd | PCMD_SUD | PCMD_POD);
    }

    /* Force interface to active state */
    uint32_t sctl = port_read(p, PORT_SCTL);
    
    port_write(p, PORT_SCTL, (sctl & ~0xFu) | 0x1u);
    
    /* brief delay via reads */
    for (int i = 0; i < 100000; i++) {
        port_read(p, PORT_SCTL);
    }

    port_write(p, PORT_SCTL, sctl & ~0xFu);

    port_start_engine(p);

    /* Verify TFD — BSY and DRQ should be clear */
    for (int i = 0; i < 0x100000; i++) {
        uint32_t tfd = port_read(p, PORT_TFD);
        
        if (!(tfd & (TFD_BSY | TFD_DRQ))) {
            break;
        }
    }

    return 0;
}

/* =========================================================================
 * Issue a single command in slot 0 and wait for completion
 * ========================================================================= */

static int port_wait_slot0(void) {
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

/* Core transfer: read or write 'count' sectors at 48-bit 'lba'.
 * Data flows through s_dma_buf to avoid alignment surprises. */
static int port_transfer(uint64_t lba, uint16_t count, void *buf, int write) {
    if (count == 0 || count > AHCI_DMA_SECTORS) {
        serial_print("[AHCI] ERROR: count out of range\n");
        
        return -1;
    }

    /* Wait for port to be idle */
    for (int i = 0; i < 0x100000; i++){
        if (!(port_read(g_port, PORT_TFD) & (TFD_BSY | TFD_DRQ))) {
            break;
        }
    }

    uint32_t byte_count = (uint32_t)count * 512u;

    if (write) {
        memcpy(s_dma_buf, buf, byte_count);
    }

    /* ----- Build command table ----- */
    memset(&s_cmd_tbl, 0, sizeof(s_cmd_tbl));

    /* H2D Register FIS in cfis[] */
    fis_h2d_t *fis = (fis_h2d_t *)s_cmd_tbl.cfis;
    fis->fis_type = FIS_TYPE_H2D;
    fis->flags = FIS_FLAG_CMD;
    fis->command = write ? ATA_WRITE_DMA_EXT : ATA_READ_DMA_EXT;
    fis->device = (1u << 6);  /* LBA mode; master device */

    /* 48-bit LBA */
    fis->lba0 = (uint8_t)(lba & 0xFFu);
    fis->lba1 = (uint8_t)((lba >>  8) & 0xFFu);
    fis->lba2 = (uint8_t)((lba >> 16) & 0xFFu);
    fis->lba3 = (uint8_t)((lba >> 24) & 0xFFu);
    fis->lba4 = (uint8_t)((lba >> 32) & 0xFFu);
    fis->lba5 = (uint8_t)((lba >> 40) & 0xFFu);

    fis->countl = (uint8_t)(count & 0xFFu);
    fis->counth = (uint8_t)((count >> 8) & 0xFFu);

    /* Single PRDT entry — points at s_dma_buf */
    uint64_t dba_phys = (uint64_t)s_dma_buf;
    s_cmd_tbl.prdt[0].dba = (uint32_t)(dba_phys & 0xFFFFFFFFu);
    s_cmd_tbl.prdt[0].dbau = (uint32_t)(dba_phys >> 32);
    s_cmd_tbl.prdt[0].dbc = byte_count - 1u;  /* zero-based byte count */

    /* ----- Build command header for slot 0 ----- */
    /*
     * flags field layout:
     *   [4:0]  CFL — Command FIS Length in DWORDs (H2D FIS = 5 DW)
     *   [5]    A   — ATAPI (0)
     *   [6]    W   — Write direction (1 = host→device)
     *   [7]    P   — Prefetch (0)
     *   [15:12] PMP — Port multiplier port (0)
     */
    s_cmd_list[0].flags = (uint16_t)(5u | (write ? (1u << 6) : 0u));
    s_cmd_list[0].prdtl = 1u;
    s_cmd_list[0].prdbc = 0u;  /* HBA will fill this in on completion */

    /* ----- Issue command and wait ----- */
    port_write(g_port, PORT_IS, 0xFFFFFFFFu);   /* clear IS */
    port_write(g_port, PORT_SERR, 0xFFFFFFFFu);   /* clear SERR */
    port_write(g_port, PORT_CI, 1u);             /* issue slot 0 */

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
 * Scans PCI bus 0 for an AHCI controller:
 *   Class = 0x01 (Mass Storage)
 *   Subclass = 0x06 (Serial ATA)
 *   Prog-IF = 0x01 (AHCI 1.0)
 *
 * Enables Memory Space and Bus Master in the PCI command register,
 * then returns BAR5 (the AHCI Base Address Register).
 */
static uint64_t pci_find_ahci_abar(void) {
    for (uint8_t dev = 0; dev < 32; dev++) {
        for (uint8_t fn = 0; fn < 8; fn++) {
            uint32_t id = pci_read32(0, dev, fn, 0x00);

            if ((id & 0xFFFF) == 0xFFFFu) {
                if (fn == 0) {
                    break;
                }

                continue;
            }

            uint32_t cc = pci_read32(0, dev, fn, 0x08);
            int is_ahci = ((cc >> 24) & 0xFF) == 0x01u && ((cc >> 16) & 0xFF) == 0x06u && ((cc >>  8) & 0xFF) == 0x01u;

            if (!is_ahci) {
                if (fn == 0) {
                    uint32_t ht = pci_read32(0, dev, 0, 0x0C);
                    
                    if (!((ht >> 16) & 0x80u)) {
                        break;
                    }
                }

                continue;
            }

            uint32_t cmd_reg = pci_read32(0, dev, fn, 0x04);

            pci_write32(0, dev, fn, 0x04, cmd_reg | 0x06u);

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

    /* --- BIOS/OS handoff (spec section 10.6) --- */
    if (hba_read(HBA_CAP2) & CAP2_BOH) {
        serial_print("[AHCI] Performing BIOS/OS handoff...\n");

        hba_write(HBA_BOHC, hba_read(HBA_BOHC) | BOHC_OOS);

        /* Wait for BIOS-owned semaphore to clear */
        for (int i = 0; i < 0x200000; i++) {
            if (!(hba_read(HBA_BOHC) & BOHC_BOS)){
                break;
            }
        }

        /* Wait for BIOS busy flag */
        for (int i = 0; i < 0x800000; i++) {
            if (!(hba_read(HBA_BOHC) & BOHC_BB)) { 
                break;
            }
        }
    }

    /* --- Enable AHCI mode --- */
    hba_write(HBA_GHC, hba_read(HBA_GHC) | GHC_AE);

    /* --- Reset HBA (clears all port state) --- */
    hba_write(HBA_GHC, hba_read(HBA_GHC) | GHC_HR);
    
    for (int i = 0; i < 0x100000; i++){
        if (!(hba_read(HBA_GHC) & GHC_HR)) {
            break;
        }
    }

    /* Re-enable AHCI after reset (reset clears AE) */
    hba_write(HBA_GHC, hba_read(HBA_GHC) | GHC_AE);

    serial_print("[AHCI] HBA version=0x");
    serial_print_hex(hba_read(HBA_VS));
    serial_print("  PI=0x");
    serial_print_hex(hba_read(HBA_PI));
    serial_print("\n");

    /* --- Find first port with a device --- */
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
        serial_print("[AHCI] ERROR: not initialised\n"); return -1; 
    }

    return port_transfer(lba, count, buf, 0);
}

int ahci_write_sectors(uint64_t lba, uint16_t count, const void *buf) {
    if (g_port < 0) { 
        serial_print("[AHCI] ERROR: not initialised\n"); return -1; 
    }

    return port_transfer(lba, count, (void *)buf, 1);
}
