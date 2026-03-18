#ifndef AHCI_H
#define AHCI_H

/* ===========================================================================
 * ahci.h — AHCI (Serial ATA) host controller driver
 *
 * Implements native SATA access via the AHCI 1.3 register interface,
 * accessed through the HBA's MMIO BAR5 (ABAR).  Works after
 * ExitBootServices because we talk directly to hardware via MMIO and
 * the PCI config-space I/O ports (0xCF8/0xCFC) — no UEFI protocols.
 *
 * Why AHCI over ATA PIO?
 *   - Native SATA: no "IDE compatibility mode" required, works on any
 *     modern chipset (Intel ICH9+, AMD FCH, etc.).
 *   - DMA transfers: the HBA moves data directly between DRAM and the
 *     drive, freeing the CPU from the tight rep-insw loop.
 *   - 48-bit LBA: address up to 128 PiB per drive, not just 128 GiB.
 *   - NCQ-ready: the command-slot design supports Native Command Queuing
 *     (we use only one slot, but the structure is already right).
 *   - Standard: every SATA controller since ~2004 speaks AHCI.
 *
 * QEMU usage
 *   pc machine (i440fx, needs explicit AHCI device):
 *     -device ich9-ahci,id=ahci
 *     -drive file=data.img,format=raw,if=none,id=data_drive
 *     -device ide-hd,drive=data_drive,bus=ahci.0
 *
 *   q35 machine (ICH9 has native AHCI at 00:1f.2):
 *     -machine q35,smm=off,accel=tcg
 *     -drive file=data.img,format=raw,if=none,id=data_drive
 *     -device ide-hd,drive=data_drive,bus=ide.2   (q35 ICH9 SATA port)
 *
 * Assumption: the kernel runs with an identity-mapped page table so
 * virtual == physical for MMIO BAR addresses.  If your VMM uses a
 * different mapping, pass the BAR through vmm_phys_to_virt() before
 * calling ahci_init_with_base().
 *
 * API
 *   ahci_init()                — PCI scan + init; returns 0 on success
 *   ahci_read_sectors(lba, n, buf)
 *   ahci_write_sectors(lba, n, buf)
 * =========================================================================== */

#include <stdint.h>

/*
 * ahci_init
 *
 * Scans PCI bus 0 for an AHCI controller (class=0x01, sub=0x06, pi=0x01).
 * Enables bus-mastering, takes BIOS→OS ownership, resets the HBA, then
 * finds the first port that has a drive attached and initialises it.
 *
 * Returns  0  on success (drive found, port ready).
 * Returns -1  if no AHCI controller is present or no drive is connected.
 */
int ahci_init(void);

/*
 * ahci_read_sectors / ahci_write_sectors
 *
 * Transfer 'count' sectors (512 B each) to/from 'buf' at 48-bit 'lba'.
 * Maximum 128 sectors (64 KB) per call — matches our largest persist
 * operation (56 sectors for the roster store).
 *
 * Returns  0  on success.
 * Returns -1  on HBA error, task-file error, or timeout.
 */
int ahci_read_sectors (uint64_t lba, uint16_t count, void       *buf);
int ahci_write_sectors(uint64_t lba, uint16_t count, const void *buf);

#endif /* AHCI_H */
