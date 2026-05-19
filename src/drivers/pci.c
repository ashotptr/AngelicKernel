#include "drivers/pci.h"
#include "config.h"
#include <stdint.h>

#define PCI_CFG_ADDR_PORT 0x0CF8u
#define PCI_CFG_DATA_PORT 0x0CFCu
#define PCI_CFG_VENDOR_ID 0x00u
#define PCI_CFG_COMMAND 0x04u
#define PCI_CFG_CLASS 0x08u
#define PCI_CFG_HEADER_TYPE 0x0Cu
#define PCI_CFG_BAR0 0x10u
#define PCI_CFG_BAR1 0x14u

#define PCI_CMD_IO_SPACE (1u << 0)
#define PCI_CMD_MEM_SPACE (1u << 1)
#define PCI_CMD_BUS_MASTER (1u << 2)
#define PCI_HEADER_MFD (1u << 7)

#define PCI_BAR_IS_IO (1u << 0)
#define PCI_BAR_MEM_TYPE_M (3u << 1)
#define PCI_BAR_MEM_TYPE_32 (0u << 1)
#define PCI_BAR_MEM_TYPE_64 (2u << 1)
#define PCI_BAR_MEM_BASE_M (~0xFu)
static inline void pci_outl(uint16_t port, uint32_t val) {
    __asm__ volatile("outl %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint32_t pci_inl(uint16_t port) {
    uint32_t v;

    __asm__ volatile("inl %1, %0" : "=a"(v) : "Nd"(port));

    return v;
}

static uint32_t pci_cfg_read32(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off) {
    uint32_t addr = (1u << 31) | ((uint32_t)bus << 16) | ((uint32_t)dev << 11) | ((uint32_t)fn << 8) | (off & 0xFCu);

    pci_outl(PCI_CFG_ADDR_PORT, addr);

    return pci_inl(PCI_CFG_DATA_PORT);
}

static void pci_cfg_write32(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off, uint32_t val) {
    uint32_t addr = (1u << 31) | ((uint32_t)bus << 16) | ((uint32_t)dev << 11) | ((uint32_t)fn << 8) | (off & 0xFCu);

    pci_outl(PCI_CFG_ADDR_PORT, addr);
    pci_outl(PCI_CFG_DATA_PORT, val);
}

static void pci_enable_device(uint8_t bus, uint8_t dev, uint8_t fn) {
    uint32_t cmd = pci_cfg_read32(bus, dev, fn, PCI_CFG_COMMAND);
    cmd |= PCI_CMD_MEM_SPACE | PCI_CMD_BUS_MASTER;

    pci_cfg_write32(bus, dev, fn, PCI_CFG_COMMAND, cmd);
}

static int device_id_matches(uint16_t vid, uint16_t did) {
    if (vid != ANGELIC_NIC_VENDOR) {
        return 0;
    }

    static const uint16_t ids[] = ANGELIC_NIC_IDS;

    for (int i = 0; ids[i] != 0x0000u; i++) {
        if (ids[i] == did) {
            return 1;
        }
    }

    return 0;
}

uint64_t pci_get_bar(uint16_t vendor_id, uint16_t device_id) {
    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint8_t dev = 0; dev < 32; dev++) {
            for (uint8_t fn = 0; fn < 8; fn++) {

                uint32_t id = pci_cfg_read32((uint8_t)bus, dev, fn, PCI_CFG_VENDOR_ID);

                if ((id & 0xFFFFu) == 0xFFFFu) {
                    if (fn == 0) {
                        break;
                    }

                    continue;
                }

                uint16_t vid = (uint16_t)(id & 0xFFFFu);
                uint16_t did = (uint16_t)((id >> 16) & 0xFFFFu);

                if (vid != vendor_id || did != device_id) {
                    if (fn == 0) {
                        uint32_t hdr = pci_cfg_read32((uint8_t)bus, dev, 0, PCI_CFG_HEADER_TYPE);

                        if (!((hdr >> 16) & PCI_HEADER_MFD)) {
                            break;
                        }
                    }

                    continue;
                }

                pci_enable_device((uint8_t)bus, dev, fn);

                uint32_t bar0 = pci_cfg_read32((uint8_t)bus, dev, fn, PCI_CFG_BAR0);

                if (bar0 & PCI_BAR_IS_IO) {
                    return 0;
                }

                uint64_t base = (uint64_t)(bar0 & (uint32_t)PCI_BAR_MEM_BASE_M);

                if ((bar0 & PCI_BAR_MEM_TYPE_M) == PCI_BAR_MEM_TYPE_64) {
                    uint32_t bar1 = pci_cfg_read32((uint8_t)bus, dev, fn, PCI_CFG_BAR1);

                    base |= ((uint64_t)bar1 << 32);
                }

                return base;
            }
        }
    }

    return 0;
}

uint64_t pci_find_nic(uint16_t *matched_did) {
    static const uint16_t ids[] = ANGELIC_NIC_IDS;

    for (int i = 0; ids[i] != 0x0000u; i++) {
        uint64_t bar = pci_get_bar(ANGELIC_NIC_VENDOR, ids[i]);

        if (bar != 0) {
            if (matched_did) {
                *matched_did = ids[i];
            }

            return bar;
        }
    }

    if (matched_did) {
        *matched_did = 0;
    }

    return 0;
}