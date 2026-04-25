/* ===========================================================================
 * pci.c — PCI Configuration Space scanner (Mechanism #1)
 *
 * Scans for any NIC in the Intel 8254x family by probing the device IDs
 * listed in config.h (ANGELIC_NIC_IDS).  All 8254x chips share the same
 * register layout, so the e1000 driver works on all of them without change.
 * Used by the E1000 NIC driver to locate the NIC's MMIO BAR.  Runs entirely
 * post-ExitBootServices: no EFI protocols, no libc — only x86 I/O ports.
 *
 * SPEC REFERENCES
 *   [PCI3]  PCI Local Bus Specification Revision 3.0
 *           §3.2.2.3.2  "Software Generation of Configuration Transactions"
 *           §6.2.2      "Device Control Register" (Command)
 *           §6.2.5.1    "Base Address Registers"
 *   [PCIID] PCI Code and ID Assignment Specification Revision 1.7
 * =========================================================================== */

#include "drivers/pci.h"
#include "config.h"
#include <stdint.h>

/* =========================================================================
 * PCI Configuration Space I/O ports — Mechanism #1
 *
 * Write a 32-bit configuration address to 0xCF8, then read or write the
 * 32-bit data register at 0xCFC.  Address format (PCI3 §3.2.2.3.2):
 *
 *   bit 31     : Enable bit — must be 1 to trigger a config cycle
 *   bits 23:16 : Bus number (0–255)
 *   bits 15:11 : Device number (0–31)
 *   bits 10:8  : Function number (0–7)
 *   bits  7:2  : Register offset, DWORD-aligned (bits 1:0 are always 0)
 * ========================================================================= */
#define PCI_CFG_ADDR_PORT  0x0CF8u
#define PCI_CFG_DATA_PORT  0x0CFCu

/* =========================================================================
 * Standard PCI Type-0 (endpoint) configuration header offsets
 * Source: PCI Local Bus Spec §6.2.1 Table 6-1
 * ========================================================================= */
#define PCI_CFG_VENDOR_ID    0x00u  /* bits 15:0  = Vendor ID                        */
                                    /* bits 31:16 = Device ID                        */
#define PCI_CFG_COMMAND      0x04u  /* bits 15:0  = Command register  — §6.2.2       */
#define PCI_CFG_CLASS        0x08u  /* bits 31:24 = Class; 23:16 = Sub; 15:8 = ProgIF */
#define PCI_CFG_HEADER_TYPE  0x0Cu  /* bits 23:16 = Header Type byte  — §6.2.1       */
#define PCI_CFG_BAR0         0x10u  /* Base Address Register 0        — §6.2.5       */
#define PCI_CFG_BAR1         0x14u  /* Base Address Register 1 (upper of 64-bit BAR0) */

/* PCI Command register bits — §6.2.2 Table 6-4 */
#define PCI_CMD_IO_SPACE    (1u << 0)  /* Enable I/O space accesses                 */
#define PCI_CMD_MEM_SPACE   (1u << 1)  /* Enable memory-mapped register access      */
#define PCI_CMD_BUS_MASTER  (1u << 2)  /* Enable bus mastering (DMA capability)     */

/* Header Type byte bit 7: set if the device is multi-function — §6.2.1 */
#define PCI_HEADER_MFD      (1u << 7)

/* BAR attribute bits (bits 3:0 of a memory BAR) — §6.2.5.1 Table 6-6 */
#define PCI_BAR_IS_IO       (1u << 0)  /* 1 = I/O space BAR, 0 = memory space BAR  */
#define PCI_BAR_MEM_TYPE_M  (3u << 1)  /* Bits 2:1: memory BAR address width        */
#define PCI_BAR_MEM_TYPE_32 (0u << 1)  /*   00 = 32-bit base address                */
#define PCI_BAR_MEM_TYPE_64 (2u << 1)  /*   10 = 64-bit base address                */
#define PCI_BAR_MEM_BASE_M  (~0xFu)    /* Mask to extract base address (strip bits 3:0) */

/* =========================================================================
 * I/O port helpers — inline asm, safe post-ExitBootServices.
 * Identical to the helpers used by ahci.c's internal PCI scanner.
 * ========================================================================= */
static inline void pci_outl(uint16_t port, uint32_t val) {
    __asm__ volatile("outl %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint32_t pci_inl(uint16_t port) {
    uint32_t v;
    __asm__ volatile("inl %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

/* =========================================================================
 * pci_cfg_read32 / pci_cfg_write32
 *
 * Read or write a 32-bit DWORD from PCI Configuration Space using
 * Mechanism #1.  'off' must be DWORD-aligned (hardware ignores bits 1:0).
 * ========================================================================= */
static uint32_t pci_cfg_read32(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off) {
    uint32_t addr = (1u << 31)
                  | ((uint32_t)bus << 16)
                  | ((uint32_t)dev << 11)
                  | ((uint32_t)fn  <<  8)
                  | (off & 0xFCu);   /* bits 1:0 always 0 — DWORD aligned */
    pci_outl(PCI_CFG_ADDR_PORT, addr);
    return pci_inl(PCI_CFG_DATA_PORT);
}

static void pci_cfg_write32(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off,
                            uint32_t val) {
    uint32_t addr = (1u << 31)
                  | ((uint32_t)bus << 16)
                  | ((uint32_t)dev << 11)
                  | ((uint32_t)fn  <<  8)
                  | (off & 0xFCu);
    pci_outl(PCI_CFG_ADDR_PORT, addr);
    pci_outl(PCI_CFG_DATA_PORT, val);
}

/* =========================================================================
 * pci_enable_device
 *
 * Set the Memory Space (bit 1) and Bus Master (bit 2) bits in the PCI
 * Command register.
 *
 *   Memory Space  — must be set before the device's MMIO BARs are accessible.
 *   Bus Master    — must be set before the device can issue DMA transactions.
 *
 * Neither bit is set by default after reset; firmware may not have set them
 * either.  Failing to set Bus Master is the most common cause of "DMA works
 * in QEMU but not on real hardware" bugs.
 * Source: PCI Local Bus Spec §6.2.2; confirmed for E1000 by SDM §14.3.
 * ========================================================================= */
static void pci_enable_device(uint8_t bus, uint8_t dev, uint8_t fn) {
    uint32_t cmd = pci_cfg_read32(bus, dev, fn, PCI_CFG_COMMAND);
    cmd |= PCI_CMD_MEM_SPACE | PCI_CMD_BUS_MASTER;
    pci_cfg_write32(bus, dev, fn, PCI_CFG_COMMAND, cmd);
}

/* ---------------------------------------------------------------------------
 * device_id_matches — check vid:did against the config.h ID table
 * --------------------------------------------------------------------------- */
static int device_id_matches(uint16_t vid, uint16_t did) {
    if (vid != ANGELIC_NIC_VENDOR) return 0;
    static const uint16_t ids[] = ANGELIC_NIC_IDS;
    for (int i = 0; ids[i] != 0x0000u; i++) {
        if (ids[i] == did) return 1;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * pci_get_bar — scan PCI bus for any supported NIC and return its BAR0
 *
 * Scans all buses/devices/functions.  Accepts any device ID listed in
 * ANGELIC_NIC_IDS (config.h) under vendor ANGELIC_NIC_VENDOR.
 *
 * The original single-ID overload is kept for callers that still pass
 * explicit IDs (e.g. AHCI scanner).
 * --------------------------------------------------------------------------- */
/* =========================================================================
 * pci_get_bar
 *
 * Scans all PCI buses (0–255), devices (0–31), and functions (0–7) for a
 * device matching (vendor_id, device_id).  When found:
 *
 *   1. Enables Memory Space + Bus Master in the PCI Command register.
 *   2. Reads and decodes BAR0:
 *        - I/O space BARs (bit 0 = 1) are not supported; returns 0.
 *        - 32-bit memory BARs (bits 2:1 = 0b00): upper 32 bits are zero.
 *        - 64-bit memory BARs (bits 2:1 = 0b10): upper 32 bits come from
 *          BAR1 (the DWORD at offset BAR0+4).
 *   3. Returns the 64-bit physical base address with attribute bits cleared.
 *
 * Returns 0 if no matching device is found.
 *
 * Notes:
 *   • The scan uses the multi-function device shortcut: if function 0 of
 *     a slot has bit 7 of its Header Type byte clear, functions 1–7 are
 *     guaranteed not to exist and are skipped.  Source: PCI3 §6.2.1.
 *   • Only BAR0 is read.  For E1000 (Intel 82540EM) this is the MMIO BAR;
 *     other devices with MMIO at a different BAR index need a separate
 *     helper or a BAR-index parameter.
 * ========================================================================= */
uint64_t pci_get_bar(uint16_t vendor_id, uint16_t device_id) {
    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint8_t dev = 0; dev < 32; dev++) {
            for (uint8_t fn = 0; fn < 8; fn++) {

                uint32_t id = pci_cfg_read32((uint8_t)bus, dev, fn,
                                             PCI_CFG_VENDOR_ID);

                /* Vendor ID 0xFFFF means no device (floating data bus).
                 * If function 0 is absent, the whole slot is empty.
                 * Source: PCI Local Bus Spec §6.1. */
                if ((id & 0xFFFFu) == 0xFFFFu) {
                    if (fn == 0) break;
                    continue;
                }

                uint16_t vid = (uint16_t)( id        & 0xFFFFu);
                uint16_t did = (uint16_t)((id >> 16) & 0xFFFFu);

                if (vid != vendor_id || did != device_id) {
                    /* Single-function device shortcut.
                     * The Header Type byte lives at config offset 0x0E
                     * (DWORD 0x0C, bits 23:16).  Bit 7 = MFD.
                     * If MFD=0 on function 0, fns 1–7 cannot exist.
                     * Source: PCI Local Bus Spec §6.2.1. */
                    if (fn == 0) {
                        uint32_t hdr = pci_cfg_read32((uint8_t)bus, dev, 0,
                                                      PCI_CFG_HEADER_TYPE);
                        if (!((hdr >> 16) & PCI_HEADER_MFD)) {
                            break;  /* single-function; skip fns 1–7 */
                        }
                    }
                    continue;
                }

                /* ---- Match found ---- */

                /* Enable Memory Space and Bus Master before any BAR access. */
                pci_enable_device((uint8_t)bus, dev, fn);

                /* Read BAR0 and check its type. */
                uint32_t bar0 = pci_cfg_read32((uint8_t)bus, dev, fn,
                                               PCI_CFG_BAR0);

                /* We only handle memory-mapped devices.  I/O space BARs
                 * (bit 0 = 1) are not used by any driver in this kernel. */
                if (bar0 & PCI_BAR_IS_IO) {
                    return 0;
                }

                /* Extract the base address (strip 4 attribute bits). */
                uint64_t base = (uint64_t)(bar0 & (uint32_t)PCI_BAR_MEM_BASE_M);

                /* 64-bit BAR: upper 32 bits reside in the next BAR slot.
                 * Source: PCI Local Bus Spec §6.2.5.1 Table 6-6. */
                if ((bar0 & PCI_BAR_MEM_TYPE_M) == PCI_BAR_MEM_TYPE_64) {
                    uint32_t bar1 = pci_cfg_read32((uint8_t)bus, dev, fn,
                                                   PCI_CFG_BAR1);
                    base |= ((uint64_t)bar1 << 32);
                }

                return base;
            }
        }
    }

    return 0;  /* device not found */
}

/* ---------------------------------------------------------------------------
 * pci_find_nic — scan for any NIC in the ANGELIC_NIC_IDS table
 *
 * Replaces the hardcoded pci_get_bar(0x8086, 0x100E) call in kernel.c.
 * Returns the MMIO BAR0 address, or 0 if no supported NIC is found.
 * Also writes the matched device_id into *matched_did if non-NULL, which
 * is useful for logging which physical chip was detected.
 * --------------------------------------------------------------------------- */
uint64_t pci_find_nic(uint16_t *matched_did) {
    static const uint16_t ids[] = ANGELIC_NIC_IDS;

    for (int i = 0; ids[i] != 0x0000u; i++) {
        uint64_t bar = pci_get_bar(ANGELIC_NIC_VENDOR, ids[i]);
        if (bar != 0) {
            if (matched_did) *matched_did = ids[i];
            return bar;
        }
    }

    if (matched_did) *matched_did = 0;
    return 0;
}