#include "drivers/ahci.h"
#include <stdint.h>
#include <string.h>

extern void serial_print(const char *s);
extern void serial_print_hex(uint64_t n);

#define PCI_CONFIG_ADDR 0x0CF8u
#define PCI_CONFIG_DATA 0x0CFCu

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

#define HBA_CAP 0x00u
#define HBA_GHC 0x04u
#define HBA_IS 0x08u
#define HBA_PI 0x0Cu
#define HBA_VS 0x10u
#define HBA_CAP2 0x24u
#define HBA_BOHC 0x28u

#define GHC_AE (1u << 31)
#define GHC_IE (1u << 1)
#define GHC_HR (1u << 0)

#define CAP_SSS (1u << 2)

#define CAP2_BOH (1u << 0)
#define BOHC_BOS (1u << 0)
#define BOHC_OOS (1u << 1)
#define BOHC_BB (1u << 4)

#define PORT_CLB 0x00u
#define PORT_CLBU 0x04u
#define PORT_FB 0x08u
#define PORT_FBU 0x0Cu
#define PORT_IS 0x10u
#define PORT_IE 0x14u
#define PORT_CMD 0x18u
#define PORT_TFD 0x20u
#define PORT_SIG 0x24u
#define PORT_SSTS 0x28u
#define PORT_SCTL 0x2Cu
#define PORT_SERR 0x30u
#define PORT_SACT 0x34u
#define PORT_CI 0x38u

#define PCMD_ST (1u << 0)
#define PCMD_SUD (1u << 1)
#define PCMD_POD (1u << 2)
#define PCMD_FRE (1u << 4)
#define PCMD_FR (1u << 14)
#define PCMD_CR (1u << 15)

#define TFD_ERR 0x01u
#define TFD_DRQ 0x08u
#define TFD_BSY 0x80u

#define SSTS_DET_MASK 0x0Fu
#define SSTS_DET_PRESENT 0x03u
#define SSTS_IPM_MASK 0xF00u
#define SSTS_IPM_ACTIVE 0x100u

#define SIG_ATA 0x00000101u
#define SIG_ATAPI 0xEB140101u
#define SIG_SEMB 0xC33C0101u
#define SIG_PM 0x96690101u

#define PIS_TFES (1u << 30)

typedef struct {
    uint16_t flags;
    uint16_t prdtl;
    uint32_t prdbc;
    uint32_t ctba;
    uint32_t ctbau;
    uint32_t _res[4];
} __attribute__((packed)) hba_cmd_hdr_t;

_Static_assert(sizeof(hba_cmd_hdr_t) == 32, "hba_cmd_hdr_t must be 32 bytes");

typedef struct {
    uint32_t dba;
    uint32_t dbau;
    uint32_t _res;
    uint32_t dbc;
} __attribute__((packed)) hba_prdt_t;

_Static_assert(sizeof(hba_prdt_t) == 16, "hba_prdt_t must be 16 bytes");

typedef struct {
    uint8_t cfis[64];
    uint8_t acmd[16];
    uint8_t _res[48];
    hba_prdt_t prdt[1];
} __attribute__((packed)) hba_cmd_tbl_t;

typedef struct {
    uint8_t fis_type;
    uint8_t flags;
    uint8_t command;
    uint8_t featurel;
    uint8_t lba0;
    uint8_t lba1;
    uint8_t lba2;
    uint8_t device;
    uint8_t lba3;
    uint8_t lba4;
    uint8_t lba5;
    uint8_t featureh;
    uint8_t countl;
    uint8_t counth;
    uint8_t icc;
    uint8_t control;
    uint8_t _res[4];
} __attribute__((packed)) fis_h2d_t;

_Static_assert(sizeof(fis_h2d_t) == 20, "fis_h2d_t must be 20 bytes");

#define FIS_TYPE_H2D 0x27u
#define FIS_FLAG_CMD 0x80u

#define ATA_READ_DMA_EXT 0x25u
#define ATA_WRITE_DMA_EXT 0x35u
#define ATA_FLUSH_EXT 0xEAu
#define ATA_IDENTIFY 0xECu

static hba_cmd_hdr_t s_cmd_list[32] __attribute__((aligned(1024)));
static uint8_t s_fis_area[256] __attribute__((aligned(256)));
static hba_cmd_tbl_t s_cmd_tbl __attribute__((aligned(128)));

#define AHCI_DMA_SECTORS 128u
static uint8_t s_dma_buf[AHCI_DMA_SECTORS * 512] __attribute__((aligned(4096)));

static volatile uint8_t *g_abar = NULL;
static int g_port = -1;

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

static void port_stop_engine(int p) {
    port_write(p, PORT_CMD, port_read(p, PORT_CMD) & ~PCMD_ST);

    for (int i = 0; i < 500000; i++) {
        if (!(port_read(p, PORT_CMD) & PCMD_CR)) {
            break;
        }
    }
    
    port_write(p, PORT_CMD, port_read(p, PORT_CMD) & ~PCMD_FRE);
    
    for (int i = 0; i < 500000; i++) {
        if (!(port_read(p, PORT_CMD) & PCMD_FR)) {
            break;
        }
    }
}

static void port_start_engine(int p) {
    for (int i = 0; i < 500000; i++) {
        if (!(port_read(p, PORT_CMD) & PCMD_CR)) {
            break;
        }
    }

    port_write(p, PORT_CMD, port_read(p, PORT_CMD) | PCMD_FRE);
    port_write(p, PORT_CMD, port_read(p, PORT_CMD) | PCMD_ST);
}

static int port_init(int p) {
    uint32_t ssts = port_read(p, PORT_SSTS);
    if ((ssts & SSTS_DET_MASK) != SSTS_DET_PRESENT) {
        return -1;
    }

    if ((ssts & SSTS_IPM_MASK) != SSTS_IPM_ACTIVE) {
        return -1;
    }

    port_stop_engine(p);

    uint64_t clb_phys = (uint64_t)(uintptr_t)s_cmd_list;
    uint64_t fb_phys = (uint64_t)(uintptr_t)s_fis_area;

    port_write(p, PORT_CLB, (uint32_t)(clb_phys & 0xFFFFFFFFu));
    port_write(p, PORT_CLBU, (uint32_t)(clb_phys >> 32));
    port_write(p, PORT_FB, (uint32_t)(fb_phys & 0xFFFFFFFFu));
    port_write(p, PORT_FBU, (uint32_t)(fb_phys >> 32));

    memset(s_cmd_list, 0, sizeof(s_cmd_list));
    memset(s_fis_area, 0, sizeof(s_fis_area));
    memset(&s_cmd_tbl, 0, sizeof(s_cmd_tbl));

    uint64_t ctba_phys = (uint64_t)(uintptr_t)&s_cmd_tbl;
    s_cmd_list[0].ctba = (uint32_t)(ctba_phys & 0xFFFFFFFFu);
    s_cmd_list[0].ctbau = (uint32_t)(ctba_phys >> 32);

    port_write(p, PORT_SERR, 0xFFFFFFFFu);
    port_write(p, PORT_IS, 0xFFFFFFFFu);

    if (hba_read(HBA_CAP) & CAP_SSS) {
        port_write(p, PORT_CMD, port_read(p, PORT_CMD) | PCMD_SUD | PCMD_POD);
    }

    uint32_t sctl = port_read(p, PORT_SCTL);

    port_write(p, PORT_SCTL, (sctl & ~0xFu) | 0x1u);

    for (volatile int i = 0; i < 20000; i++) {
        (void)port_read(p, PORT_SCTL);
    }

    port_write(p, PORT_SCTL, sctl & ~0xFu);

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

    uint32_t sig = port_read(p, PORT_SIG);

    if (sig != SIG_ATA) {
        serial_print("[ahci] port sig=0x");
        serial_print_hex(sig);
        serial_print("— not an ata drive, skipping\n");

        return -1;
    }

    port_start_engine(p);

    for (int i = 0; i < 0x100000; i++) {
        if (!(port_read(p, PORT_TFD) & (TFD_BSY | TFD_DRQ))) {
            break;
        }
    }

    return 0;
}

static int port_wait_slot0(void) {
    for (uint32_t i = 0; i < 0x2000000u; i++) {
        if (port_read(g_port, PORT_IS) & PIS_TFES) {
            serial_print("[ahci] task file error (tfd=0x");
            serial_print_hex(port_read(g_port, PORT_TFD));
            serial_print(")\n");

            port_write(g_port, PORT_IS, 0xFFFFFFFFu);
            port_write(g_port, PORT_SERR, 0xFFFFFFFFu);

            return -1;
        }

        if (!(port_read(g_port, PORT_CI) & 1u)) {
            return 0;
        }
    }

    serial_print("[ahci] command timeout, slot 0 never cleared\n");

    port_write(g_port, PORT_IS, 0xFFFFFFFFu);
    port_write(g_port, PORT_SERR, 0xFFFFFFFFu);

    return -1;
}

static int port_flush(void) {
    for (int i = 0; i < 0x100000; i++) {
        if (!(port_read(g_port, PORT_TFD) & (TFD_BSY | TFD_DRQ))) {
            break;
        }
    }

    memset(&s_cmd_tbl, 0, sizeof(s_cmd_tbl));

    fis_h2d_t *fis = (fis_h2d_t *)s_cmd_tbl.cfis;
    fis->fis_type = FIS_TYPE_H2D;
    fis->flags = FIS_FLAG_CMD;
    fis->command = ATA_FLUSH_EXT;
    fis->device = (1u << 6);

    s_cmd_list[0].flags = 5u;
    s_cmd_list[0].prdtl = 0u;
    s_cmd_list[0].prdbc = 0u;

    port_write(g_port, PORT_IS, 0xFFFFFFFFu);
    port_write(g_port, PORT_SERR, 0xFFFFFFFFu);
    port_write(g_port, PORT_CI, 1u);

    return port_wait_slot0();
}

static int port_transfer(uint64_t lba, uint16_t count, void *buf, int write) {
    if (count == 0 || count > AHCI_DMA_SECTORS) {
        serial_print("[ahci] count out of range\n");

        return -1;
    }

    for (int i = 0; i < 0x100000; i++) {
        if (!(port_read(g_port, PORT_TFD) & (TFD_BSY | TFD_DRQ))) {
            break;
        }
    }

    uint32_t byte_count = (uint32_t)count * 512u;

    if (write) {
        memcpy(s_dma_buf, buf, byte_count);
    }

    memset(&s_cmd_tbl, 0, sizeof(s_cmd_tbl));

    fis_h2d_t *fis = (fis_h2d_t *)s_cmd_tbl.cfis;
    fis->fis_type = FIS_TYPE_H2D;
    fis->flags = FIS_FLAG_CMD;
    fis->command = write ? ATA_WRITE_DMA_EXT : ATA_READ_DMA_EXT;

    fis->device = (1u << 6);

    fis->lba0 = (uint8_t)(lba & 0xFFu);
    fis->lba1 = (uint8_t)((lba >> 8) & 0xFFu);
    fis->lba2 = (uint8_t)((lba >> 16) & 0xFFu);
    fis->lba3 = (uint8_t)((lba >> 24) & 0xFFu);
    fis->lba4 = (uint8_t)((lba >> 32) & 0xFFu);
    fis->lba5 = (uint8_t)((lba >> 40) & 0xFFu);

    fis->countl = (uint8_t)(count & 0xFFu);
    fis->counth = (uint8_t)((count >> 8) & 0xFFu);

    uint64_t dba_phys = (uint64_t)(uintptr_t)s_dma_buf;
    s_cmd_tbl.prdt[0].dba = (uint32_t)(dba_phys & 0xFFFFFFFFu);
    s_cmd_tbl.prdt[0].dbau = (uint32_t)(dba_phys >> 32);
    s_cmd_tbl.prdt[0].dbc = byte_count - 1u;

    s_cmd_list[0].flags = (uint16_t)(5u | (write ? (1u << 6) : 0u));
    s_cmd_list[0].prdtl = 1u;
    s_cmd_list[0].prdbc = 0u;

    port_write(g_port, PORT_IS, 0xFFFFFFFFu);
    port_write(g_port, PORT_SERR, 0xFFFFFFFFu);
    port_write(g_port, PORT_CI, 1u);

    if (port_wait_slot0() != 0) {
        return -1;
    }

    if (!write) {
        memcpy(buf, s_dma_buf, byte_count);
    }
    else {
        if (port_flush() != 0) {
            serial_print("[ahci] warning: flush cache ext failed, data may not be durable\n");
        }
    }

    return 0;
}

static uint64_t pci_find_ahci_abar(void) {
    for (uint8_t dev = 0; dev < 32; dev++) {
        for (uint8_t fn = 0; fn < 8; fn++) {
            uint32_t id = pci_read32(0, dev, fn, 0x00);

            if ((id & 0xFFFFu) == 0xFFFFu) {
                if (fn == 0) {
                    break;
                }

                continue;
            }

            uint32_t cc = pci_read32(0, dev, fn, 0x08);
            int is_ahci = ((cc >> 24) & 0xFFu) == 0x01u && ((cc >> 16) & 0xFFu) == 0x06u && ((cc >>  8) & 0xFFu) == 0x01u;

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

            serial_print("[ahci] controller found pci 0:");
            serial_print_hex(dev);
            serial_print(".");
            serial_print_hex(fn);
            serial_print("abar=0x");
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
        serial_print("[ahci] no controller found\n");

        return -1;
    }

    g_abar = (volatile uint8_t *)(uintptr_t)abar;

    if (hba_read(HBA_CAP2) & CAP2_BOH) {
        serial_print("[ahci] performing bios/os handoff\n");

        hba_write(HBA_BOHC, hba_read(HBA_BOHC) | BOHC_OOS);
        
        for (int i = 0; i < 0x200000; i++) {
            if (!(hba_read(HBA_BOHC) & BOHC_BOS)) {
                break;
            }
        }
        
        if (hba_read(HBA_BOHC) & BOHC_BB) {
            for (int i = 0; i < 0x800000; i++) {
                if (!(hba_read(HBA_BOHC) & BOHC_BB)) {
                    break;
                }
            }
        }
    }

    hba_write(HBA_GHC, hba_read(HBA_GHC) | GHC_AE);

    hba_write(HBA_GHC, hba_read(HBA_GHC) | GHC_HR);

    int reset_ok = 0;

    for (int i = 0; i < 0x100000; i++) {
        if (!(hba_read(HBA_GHC) & GHC_HR)) {
            reset_ok = 1;

            break;
        }
    }

    if (!reset_ok) {
        serial_print("[ahci] hba reset did not complete (ghc.hr stuck)\n");

        return -1;
    }

    hba_write(HBA_GHC, hba_read(HBA_GHC) | GHC_AE);

    serial_print("[ahci] hba version=0x");
    serial_print_hex(hba_read(HBA_VS));
    serial_print("PI=0x");
    serial_print_hex(hba_read(HBA_PI));
    serial_print("\n");

    uint32_t pi = hba_read(HBA_PI);
    for (int p = 0; p < 32; p++) {
        if (!(pi & (1u << p))) {
            continue;
        }

        serial_print("[ahci] probing port ");
        serial_print_hex((uint64_t)p);
        serial_print("ssts=0x");
        serial_print_hex(port_read(p, PORT_SSTS));
        serial_print("sig=0x");
        serial_print_hex(port_read(p, PORT_SIG));
        serial_print("\n");

        if (port_init(p) == 0) {
            g_port = p;

            serial_print("[ahci] initialised port ");
            serial_print_hex((uint64_t)p);
            serial_print("\n");
            
            return 0;
        }
    }

    serial_print("[ahci] no ata drive found on any implemented port\n");
    
    return -1;
}

int ahci_read_sectors(uint64_t lba, uint16_t count, void *buf) {
    if (g_port < 0) {
        serial_print("[ahci] not initialised\n");

        return -1;
    }

    return port_transfer(lba, count, buf, 0);
}

int ahci_write_sectors(uint64_t lba, uint16_t count, const void *buf) {
    if (g_port < 0) {
        serial_print("[ahci] not initialised\n");

        return -1;
    }

    return port_transfer(lba, count, (void *)buf, 1);
}