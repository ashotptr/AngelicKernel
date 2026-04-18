/* ===========================================================================
 * e1000.c — Intel 8254x (E1000) Gigabit Ethernet Controller driver
 *
 * Supports the QEMU/KVM "e1000" device (Intel 82540EM, PCI 8086:100E) and
 * any controller in the 8254x series: 82540EP/EM, 82541xx, 82544GC/EI,
 * 82545GM/EM, 82546GB/EB, 82547xx.
 *
 * Uses legacy transmit and receive descriptor rings with MMIO register
 * access and polled (non-interrupt-driven) packet reception.
 *
 * Runs entirely post-ExitBootServices.  No EFI protocols, no libc heap,
 * no threads.  Descriptor rings and their DMA state live in the
 * .secure_driver_data section (MPK-protected from kernel code).
 *
 * SPEC REFERENCES
 *   [SDM]   Intel® PCI/PCI-X Family of Gigabit Ethernet Controllers
 *           Software Developer's Manual Rev 2.5
 *           (82540EP/EM, 82541xx, 82544GC/EI, 82545GM/EM,
 *            82546GB/EB, 82547xx)
 *           https://www.intel.com/content/dam/doc/manual/
 *           pci-pci-x-family-gbe-controllers-software-dev-manual.pdf
 *   [OSDEV] https://wiki.osdev.org/Intel_8254x
 *
 * INITIALISATION SEQUENCE — SDM §14.3 "General Configuration":
 *   1.  Software reset via CTRL.RST (bit 26, self-clearing)
 *   2.  Set CTRL.SLU and CTRL.ASDE (link up + auto-speed detection)
 *   3.  Read MAC from RAL[0] / RAH[0]
 *   4.  Set up receive descriptor ring (RDBAL/RDBAH/RDLEN/RDH/RDT)
 *   5.  Set up transmit descriptor ring (TDBAL/TDBAH/TDLEN/TDH/TDT)
 *   6.  Write TIPG with 802.3-compliant inter-packet gap values
 *   7.  Configure RCTL (receive control)
 *   8.  Configure TCTL (transmit control)
 *   9.  Unmask required interrupts in IMS; clear ICR
 * =========================================================================== */

#include "drivers/e1000.h"
#include "sys/mpk_sections.h"
#include "mm/pmm.h"
#include <stdint.h>
#include <string.h>

extern void serial_print(const char *s);
extern void serial_print_hex(uint64_t n);

/* =========================================================================
 * Register map — SDM Table 13-2 (§13.2, p. 219)
 *
 * All offsets are relative to the MMIO BAR0 base address.
 * Register width is always 32 bits (one DWORD).
 * ========================================================================= */

/* ---- General ---- */
#define E1000_CTRL    0x0000u  /* Device Control                       — SDM §13.3  */
#define E1000_STATUS  0x0008u  /* Device Status (read-only)            — SDM §13.4  */
#define E1000_EECD    0x0010u  /* EEPROM/Flash Control                 — SDM §13.6  */
#define E1000_EERD    0x0014u  /* EEPROM Read                          — SDM §13.7  */

/* ---- Interrupt ---- */
#define E1000_ICR     0x00C0u  /* Interrupt Cause Read (R/auto-clear)  — SDM §13.51 */
#define E1000_ICS     0x00C8u  /* Interrupt Cause Set (W)              — SDM §13.52 */
#define E1000_IMS     0x00D0u  /* Interrupt Mask Set / Read            — SDM §13.53 */
#define E1000_IMC     0x00D8u  /* Interrupt Mask Clear (W)             — SDM §13.54 */

/* ---- Receive ---- */
#define E1000_RCTL    0x0100u  /* Receive Control                      — SDM §13.61 */
#define E1000_RDBAL   0x2800u  /* RX Desc. Base Address Low            — SDM §13.72 */
#define E1000_RDBAH   0x2804u  /* RX Desc. Base Address High           — SDM §13.73 */
#define E1000_RDLEN   0x2808u  /* RX Descriptor Ring Length (bytes)    — SDM §13.74 */
#define E1000_RDH     0x2810u  /* RX Descriptor Head (hw-owned)        — SDM §13.75 */
#define E1000_RDT     0x2818u  /* RX Descriptor Tail (sw-owned)        — SDM §13.76 */
#define E1000_RDTR    0x2820u  /* RX Interrupt Delay Timer             — SDM §13.77 */

/* ---- Transmit ---- */
#define E1000_TCTL    0x0400u  /* Transmit Control                     — SDM §13.88 */
#define E1000_TIPG    0x0410u  /* Transmit Inter-Packet Gap            — SDM §13.91 */
#define E1000_TDBAL   0x3800u  /* TX Desc. Base Address Low            — SDM §13.95 */
#define E1000_TDBAH   0x3804u  /* TX Desc. Base Address High           — SDM §13.96 */
#define E1000_TDLEN   0x3808u  /* TX Descriptor Ring Length (bytes)    — SDM §13.97 */
#define E1000_TDH     0x3810u  /* TX Descriptor Head (hw-owned)        — SDM §13.98 */
#define E1000_TDT     0x3818u  /* TX Descriptor Tail (sw-owned)        — SDM §13.99 */

/* ---- Receive Address (16 slots, 8 bytes each) ---- */
#define E1000_RAL0    0x5400u  /* Receive Address Low  [0]: MAC bytes 0–3 — §13.147 */
#define E1000_RAH0    0x5404u  /* Receive Address High [0]: MAC bytes 4–5 — §13.148 */
                               /*   bit 31 = Address Valid (AV) bit        */

/* =========================================================================
 * CTRL register bits — SDM §13.3 Table 13-3
 * ========================================================================= */
#define E1000_CTRL_FD      (1u <<  0)  /* Full Duplex                              */
#define E1000_CTRL_ASDE    (1u <<  5)  /* Auto-Speed Detection Enable              */
#define E1000_CTRL_SLU     (1u <<  6)  /* Set Link Up — must set on real hardware  */
#define E1000_CTRL_ILOS    (1u <<  7)  /* Invert Loss-of-Signal (rarely needed)    */
#define E1000_CTRL_SPEED_M (3u <<  8)  /* Speed field mask (bits 9:8)              */
#define E1000_CTRL_FRCSPD  (1u << 11)  /* Force Speed using SPEED field            */
#define E1000_CTRL_FRCDPLX (1u << 12)  /* Force Duplex using FD bit                */
#define E1000_CTRL_RST     (1u << 26)  /* Software Reset (self-clearing) — §14.3   */
#define E1000_CTRL_RFCE    (1u << 27)  /* Receive Flow Control Enable              */
#define E1000_CTRL_TFCE    (1u << 28)  /* Transmit Flow Control Enable             */
#define E1000_CTRL_VME     (1u << 30)  /* VLAN Mode Enable                         */
#define E1000_CTRL_PHY_RST (1u << 31)  /* PHY Reset                                */

/* =========================================================================
 * RCTL register bits — SDM §13.61 Table 13-67
 * ========================================================================= */
#define E1000_RCTL_EN          (1u <<  1)  /* Receiver Enable                      */
#define E1000_RCTL_SBP         (1u <<  2)  /* Store Bad Packets                    */
#define E1000_RCTL_UPE         (1u <<  3)  /* Unicast Promiscuous Enable           */
#define E1000_RCTL_MPE         (1u <<  4)  /* Multicast Promiscuous Enable         */
#define E1000_RCTL_LPE         (1u <<  5)  /* Long Packet Enable (>1522 bytes)     */
#define E1000_RCTL_LBM_NONE    (0u <<  6)  /* No loopback                          */
#define E1000_RCTL_RDMTS_HALF  (0u <<  8)  /* RX Desc threshold = 1/2 RDLEN       */
#define E1000_RCTL_BAM         (1u << 15)  /* Broadcast Accept Mode                */
/* Buffer size (bits 17:16, BSIZE), valid when BSEX=0:                            */
#define E1000_RCTL_BSIZE_2048  (0u << 16)  /* 2048-byte receive buffers (default) */
#define E1000_RCTL_BSIZE_1024  (1u << 16)
#define E1000_RCTL_BSIZE_512   (2u << 16)
#define E1000_RCTL_BSIZE_256   (3u << 16)
#define E1000_RCTL_VFE         (1u << 18)  /* VLAN Filter Enable                   */
#define E1000_RCTL_BSEX        (1u << 25)  /* Buffer Size Extension (×16)          */
#define E1000_RCTL_SECRC       (1u << 26)  /* Strip Ethernet CRC from received frames */

/* =========================================================================
 * TCTL register bits — SDM §13.88 Table 13-95
 * ========================================================================= */
#define E1000_TCTL_EN          (1u <<  1)  /* Transmit Enable                       */
#define E1000_TCTL_PSP         (1u <<  3)  /* Pad Short Packets to 64 bytes         */
/* CT (Collision Threshold, bits 11:4) — meaningful only in half-duplex mode.     */
#define E1000_TCTL_CT(n)       (((uint32_t)(n) & 0xFFu) <<  4)
/* COLD (Collision Distance, bits 21:12):
 *   Full-duplex : 0x03F  (64 byte-times)
 *   Half-duplex : 0x1FF  (512 byte-times)
 * Source: SDM §14.5 step 5.                                                      */
#define E1000_TCTL_COLD(n)     (((uint32_t)(n) & 0x3FFu) << 12)
#define E1000_TCTL_RTLC        (1u << 24)  /* Re-Transmit on Late Collision         */

/* =========================================================================
 * TIPG — Transmit Inter-Packet Gap — SDM §13.91
 *
 * Three sub-fields packed into one DWORD:
 *   IPGT  bits  9:0  — Inter-Packet Gap Transmit Time
 *   IPGR1 bits 19:10 — IPG Receive Time 1
 *   IPGR2 bits 29:20 — IPG Receive Time 2
 *
 * IEEE 802.3 recommended values for 8254x (SDM §14.5 Table 14-2):
 *   IPGT=8, IPGR1=4, IPGR2=6  →  0x00602008
 *
 * Failure to write TIPG before enabling the transmitter will cause
 * timing violations on real hardware, potentially preventing any packet
 * from being sent.  QEMU's emulator is more forgiving, but the register
 * must still be set per the initialisation checklist.
 * ========================================================================= */
#define E1000_TIPG_802_3  (8u | (4u << 10) | (6u << 20))  /* = 0x00602008 */

/* =========================================================================
 * IMS / ICR bit definitions — SDM §13.53 Table 13-58
 * ========================================================================= */
#define E1000_IMS_TXDW    (1u << 0)  /* Transmit Descriptor Written Back          */
#define E1000_IMS_LSC     (1u << 2)  /* Link Status Change (cable plug/unplug)    */
#define E1000_IMS_RXDMT0  (1u << 4)  /* RX Descriptor Minimum Threshold reached   */
#define E1000_IMS_RXO     (1u << 6)  /* Receiver Overrun (ring full — missed pkt) */
#define E1000_IMS_RXT0    (1u << 7)  /* Receiver Timer Interrupt (packet arrived) */

/* =========================================================================
 * Transmit descriptor bits (legacy format) — SDM §3.3.3 Table 3-1
 * ========================================================================= */
/* cmd field */
#define E1000_TXD_CMD_EOP   (1u << 0)  /* End Of Packet                           */
#define E1000_TXD_CMD_IFCS  (1u << 1)  /* Insert FCS/CRC                          */
#define E1000_TXD_CMD_RS    (1u << 3)  /* Report Status — HW sets DD when done    */
/* status field */
#define E1000_TXD_STAT_DD   (1u << 0)  /* Descriptor Done — packet has been sent  */

/* =========================================================================
 * Receive descriptor bits (legacy format) — SDM §3.2.3 Table 3-1
 * ========================================================================= */
/* status field */
#define E1000_RXD_STAT_DD   (1u << 0)  /* Descriptor Done — frame has been placed */
#define E1000_RXD_STAT_EOP  (1u << 1)  /* End Of Packet — descriptor ends frame   */

/* =========================================================================
 * TX completion timeout
 *
 * Bounded iteration count to avoid an infinite hang if the NIC stops
 * responding.  On QEMU/KVM the TDT→DD round-trip is typically sub-μs.
 * Under TCG emulation it is slower, but 0x100000 iterations still gives
 * several hundred milliseconds — far beyond any legitimate send time.
 * ========================================================================= */
#define E1000_TX_TIMEOUT  0x100000u

/* =========================================================================
 * Driver state — all in the MPK-protected section
 *
 * e1000_mmio_base_phys is placed alongside the descriptor rings it controls.
 * Kernel code in the unprotected section cannot corrupt the NIC control plane
 * without first passing through the MPK gate.
 * ========================================================================= */
SECURE_DRIVER_DATA static uint64_t e1000_mmio_base_phys;

/* Shared TX tail index — used by BOTH e1000_send_raw() and e1000_send_scatter().
 * Placed in .secure_driver_data so it lives alongside the descriptor rings
 * it indexes and is equally protected by MPK Key 1.
 */
SECURE_DRIVER_DATA static int tx_tail = 0;

SECURE_DRIVER_DATA volatile struct e1000_rx_desc rx_ring[RX_RING_SIZE] __attribute__((aligned(16)));
SECURE_DRIVER_DATA volatile struct e1000_tx_desc tx_ring[TX_RING_SIZE] __attribute__((aligned(16)));

/* =========================================================================
 * MMIO register accessors — internal use only
 *
 * Declared static to prevent the unprotected kernel from calling these
 * directly.  The public API (e1000_init / e1000_send_raw / e1000_poll_receive)
 * is the only entry point through the MPK gate.
 * ========================================================================= */
SECURE_DRIVER_CODE static inline void nic_write(uint32_t reg, uint32_t val) {
    *(volatile uint32_t *)(e1000_mmio_base_phys + reg) = val;
}

SECURE_DRIVER_CODE static inline uint32_t nic_read(uint32_t reg) {
    return *(volatile uint32_t *)(e1000_mmio_base_phys + reg);
}

/* ─── Put this function in src/drivers/e1000.c ───────────────────────────── */

SECURE_DRIVER_CODE int e1000_send_scatter(uint64_t mmio_base,
                                           const void **addrs,
                                           const uint16_t *lens,
                                           int n_segs) {
    (void)mmio_base;
 
    if (n_segs <= 0 || n_segs > TX_RING_SIZE / 2) return -1;
 
 
    // Check that there are enough free TX descriptors.
    // A descriptor is free when its DD (Descriptor Done) bit is set,
    // meaning the NIC finished DMAing the previous packet from that slot.
    int first_idx = tx_tail;
    for (int i = 0; i < n_segs; i++) {
        int slot = (tx_tail + i) % TX_RING_SIZE;
        if (!(tx_ring[slot].status & E1000_TXD_STAT_DD)) {
            // Ring is full — wait for the oldest pending descriptor.
            for (uint32_t t = 0; t < E1000_TX_TIMEOUT; t++) {
                if (tx_ring[slot].status & E1000_TXD_STAT_DD) break;
            }
            if (!(tx_ring[slot].status & E1000_TXD_STAT_DD)) return -1;
        }
    }
 
    // Write descriptors for all segments.
    for (int i = 0; i < n_segs; i++) {
        int slot = (tx_tail + i) % TX_RING_SIZE;
        int is_last = (i == n_segs - 1);
 
        tx_ring[slot].addr   = (uint64_t)(uintptr_t)addrs[i];
        tx_ring[slot].length = lens[i];
        tx_ring[slot].cso    = 0;
        tx_ring[slot].css    = 0;
        tx_ring[slot].special = 0;

        tx_ring[slot].cmd = E1000_TXD_CMD_IFCS | E1000_TXD_CMD_RS |
                    (is_last ? E1000_TXD_CMD_EOP : 0);
        tx_ring[slot].status = 0;   // clear DD
    }
 
    int last_idx = (tx_tail + n_segs - 1) % TX_RING_SIZE;
    tx_tail = (tx_tail + n_segs) % TX_RING_SIZE;
 
    __asm__ volatile("" ::: "memory");   // compiler barrier
 
    // Kick the NIC: write TDT to the NEXT free slot.
    nic_write(E1000_TDT, (uint32_t)tx_tail);
 
    // Poll only the last descriptor for DD.
    for (uint32_t t = 0; t < E1000_TX_TIMEOUT; t++) {
        if (tx_ring[last_idx].status & E1000_TXD_STAT_DD) return 0;
    }
 
    serial_print("[E1000] ERROR: scatter TX timeout\n");
    return -1;
}

/* =========================================================================
 * e1000_init
 *
 * Performs the full 8254x initialisation sequence as documented in
 * SDM §14.3 "General Configuration" and the OSDev 8254x page.
 *
 * Parameters:
 *   mmio_base — MMIO BAR0 physical address, obtained from pci_get_bar()
 *   mac_out   — if non-NULL, receives the 6-byte MAC address on success
 *
 * Returns 0 on success, -1 if any allocation fails.
 * ========================================================================= */
SECURE_DRIVER_CODE int e1000_init(uint64_t mmio_base, uint8_t *mac_out) {
    e1000_mmio_base_phys = mmio_base;

    // In .secure_driver_data, we must zero them manually, because the NIC will read garbage descriptors and overwrite random memory (like your Kernel Code!) via DMA.
    /* -----------------------------------------------------------------
     * Step 1: Software reset — CTRL.RST (bit 26), self-clearing.
     *
     * This returns all registers to their power-on defaults, flushing
     * any state left by firmware or a prior OS.  We must poll until the
     * bit clears before touching any other register.
     *
     * IMPORTANT: the previous code set bit 6 (SLU = Set Link Up) instead
     * of bit 26 (RST).  That was not a reset at all.
     *
     * QEMU note: builds prior to June 2009 did not process CTRL.RST
     * correctly.  Modern QEMU (4.x+) handles it properly.
     * Source: SDM §14.3 step 1; OSDev "Intel 8254x" §General.
     * ----------------------------------------------------------------- */
    nic_write(E1000_CTRL, nic_read(E1000_CTRL) | E1000_CTRL_RST);

    /* Poll until RST self-clears (hardware guarantee). */
    for (uint32_t i = 0; i < 0x20000u; i++) {
        if (!(nic_read(E1000_CTRL) & E1000_CTRL_RST)) {
            break;
        }
    }

    /* -----------------------------------------------------------------
     * Step 2: Set Link Up + Auto-Speed Detection.
     *
     * CTRL.SLU (bit 6) asserts the link to the PHY.  On real hardware
     * the link will not come up without this.  QEMU forces the link up
     * regardless, but setting it explicitly is correct per the spec.
     *
     * CTRL.ASDE (bit 5) tells the MAC to auto-detect the PHY's speed
     * instead of reading the SPEED field.  Required for Gigabit operation
     * when FRCSPD is not set.
     * Source: SDM §14.3 step 3.
     * ----------------------------------------------------------------- */
    nic_write(E1000_CTRL, nic_read(E1000_CTRL) | E1000_CTRL_SLU | E1000_CTRL_ASDE);

    /* -----------------------------------------------------------------
     * Step 3: Read MAC address from RAL[0] / RAH[0].
     *
     * On reset the NIC loads the MAC from EEPROM into the Receive Address
     * registers.  In QEMU the -net mac= or -netdev mac= option sets this.
     * RAL[0] = bytes 0–3 (little-endian), RAH[0] bits 15:0 = bytes 4–5.
     * Source: SDM §13.147–148; §14.7 "Receive Initialization".
     * ----------------------------------------------------------------- */
    uint32_t ral = nic_read(E1000_RAL0); // E1000_RAL, RAL (Receive Address Low)
    uint32_t rah = nic_read(E1000_RAH0); // E1000_RAH, RAH (Receive Address High).

    if (mac_out) {
        mac_out[0] = (uint8_t)( ral        & 0xFFu);
        mac_out[1] = (uint8_t)((ral >>  8) & 0xFFu);
        mac_out[2] = (uint8_t)((ral >> 16) & 0xFFu);
        mac_out[3] = (uint8_t)((ral >> 24) & 0xFFu);
        mac_out[4] = (uint8_t)( rah        & 0xFFu);
        mac_out[5] = (uint8_t)((rah >>  8) & 0xFFu);
    }

    /* -----------------------------------------------------------------
     * Step 4: Receive descriptor ring.
     *
     * We allocate one 4 KB page per ring slot as the DMA receive buffer.
     * The .secure_driver_data section is NOT zero-initialised by the CRT
     * (it lives in a custom linker section with no load-time clearing),
     * so we must initialise every field manually before handing the ring
     * to the NIC.  An uninitialised addr field would cause the NIC to
     * DMA received data to a random physical address — a silent memory
     * corruption.
     *
     * Ring ownership rule (SDM §14.7):
     *   Hardware owns descriptors from RDH up to (but not including) RDT.
     *   Software owns the rest.  Setting RDT = RX_RING_SIZE−1 with RDH=0
     *   gives every slot to the hardware immediately after initialisation.
     * ----------------------------------------------------------------- */
    for (int i = 0; i < RX_RING_SIZE; i++) {
        void *buf = pmm_alloc_page();
        if (!buf) {
            serial_print("[E1000] ERROR: out of physical pages for RX ring\n");
            return -1;
        }
        rx_ring[i].addr     = (uint64_t)(uintptr_t)buf;
        rx_ring[i].length   = 0;
        rx_ring[i].checksum = 0;
        rx_ring[i].status   = 0;
        rx_ring[i].errors   = 0;
        rx_ring[i].special  = 0;
    }

    uint64_t rx_phys = (uint64_t)(uintptr_t)rx_ring;
    nic_write(E1000_RDBAL, (uint32_t)( rx_phys        & 0xFFFFFFFFu)); // RDBAL (Receive Descriptor Base Address Low)
    nic_write(E1000_RDBAH, (uint32_t)( rx_phys >> 32)); // RDBAH (Receive Descriptor Base Address High)
    nic_write(E1000_RDLEN, (uint32_t)( RX_RING_SIZE * sizeof(struct e1000_rx_desc))); // RDLEN (Receive Descriptor Length)
    
    // Initialize Head and Tail
    nic_write(E1000_RDH,   0u); // RDH (Head)
    
    /* RDT = last descriptor index.  Giving RDT=N-1, RDH=0 hands all N
     * slots to hardware immediately.  Source: SDM §14.7 step 4. */
    nic_write(E1000_RDT,   (uint32_t)(RX_RING_SIZE - 1)); // RDT (Tail) - Start at end so all descriptors are available

    /* -----------------------------------------------------------------
     * Step 5: Transmit descriptor ring.
     *
     * Pre-mark every TX descriptor's status DD=1.  This prevents
     * e1000_send_raw from confusing a fresh descriptor with a pending one
     * if it wraps around the ring before the previous slot has been
     * cleared by hardware.  The NIC overwrites status on actual sends.
     * Source: SDM §14.5 "Transmit Initialization".
     * ----------------------------------------------------------------- */
    for (int i = 0; i < TX_RING_SIZE; i++) {
        tx_ring[i].addr    = 0;
        tx_ring[i].length  = 0;
        tx_ring[i].cso     = 0;
        tx_ring[i].cmd     = 0;
        tx_ring[i].status  = E1000_TXD_STAT_DD;  /* pre-mark as done */
        tx_ring[i].css     = 0;
        tx_ring[i].special = 0;
    }

    uint64_t tx_phys = (uint64_t)(uintptr_t)tx_ring;
    nic_write(E1000_TDBAL, (uint32_t)( tx_phys        & 0xFFFFFFFFu)); // TDBAL
    nic_write(E1000_TDBAH, (uint32_t)( tx_phys >> 32)); // TDBAH
    nic_write(E1000_TDLEN, (uint32_t)( TX_RING_SIZE * sizeof(struct e1000_tx_desc))); // TDLEN
    
    // Initialize Head and Tail
    nic_write(E1000_TDH,   0u); // TDH (Head)
    nic_write(E1000_TDT,   0u); // TDT (Tail)

    /* -----------------------------------------------------------------
     * Step 6: Transmit Inter-Packet Gap (TIPG) — MANDATORY.
     *
     * TIPG must be written before enabling the transmitter.  Using the
     * power-on default (all-zeros) causes timing violations on real
     * hardware.  The 802.3 values (IPGT=8, IPGR1=4, IPGR2=6) produce
     * the standard 96-bit inter-frame gap.
     * Source: SDM §14.5 step 4; §13.91.
     * ----------------------------------------------------------------- */
    nic_write(E1000_TIPG, E1000_TIPG_802_3);

    /* -----------------------------------------------------------------
     * Step 7: Receive Control (RCTL).
     *
     *   EN    — enable receiver
     *   MPE   — accept all multicast (required for mDNS / link-local)
     *   BAM   — accept broadcast frames
     *   BSIZE — 2048-byte buffers (BSEX=0, BSIZE=0b00)
     *   SECRC — strip the 4-byte Ethernet FCS from received frames
     *           so the upper layer never sees it; consistent with how
     *           lwIP expects to receive raw Ethernet frames.
     * Source: SDM §14.7; §13.61.
     * ----------------------------------------------------------------- */
     // Set RCTL: EN | SBP | UPE | MPE | LBM_NONE | RDMTS_HALF | BAM | SECRC | BSIZE_2048
    // 1 << 1 (EN): Enable Receiver. Turns the radio on.
    // 1 << 4 (MPE): Multicast Promiscuous Enabled. Accepts multicast packets.
    // 1 << 15 (BAM): Broadcast Accept Mode. Accepts broadcast packets.
    // 1 << 26 (SECRC): Strip Ethernet CRC. The hardware removes the last 4 bytes (checksum) so there is no need to process them in software.
    nic_write(E1000_RCTL,
              E1000_RCTL_EN          |
              E1000_RCTL_MPE         |
              E1000_RCTL_BAM         |
              E1000_RCTL_BSIZE_2048  |
              E1000_RCTL_SECRC);

    /* -----------------------------------------------------------------
     * Step 8: Transmit Control (TCTL).
     *
     *   EN    — enable transmitter
     *   PSP   — pad short frames to 64 bytes (required by 802.3)
     *   CT    — collision threshold 0x0F (relevant only in half-duplex)
     *   COLD  — collision distance 0x03F (full-duplex = 64 byte-times)
     * Source: SDM §14.5; §13.88.
     * ----------------------------------------------------------------- */
    // Set TCTL: EN | PSP | CT=15 | COLD=64
    nic_write(E1000_TCTL,
              E1000_TCTL_EN        |
              E1000_TCTL_PSP       |
              E1000_TCTL_CT(0x0F)  |
              E1000_TCTL_COLD(0x03F));

    /* -----------------------------------------------------------------
     * Step 9: Interrupt configuration.
     *
     * Clear any interrupts that arrived during the init sequence (ICR is
     * read-to-clear), then unmask the interrupts we care about:
     *
     *   RXT0 — packet received (most important for polled receive)
     *   RXO  — receive overrun (ring full; helps detect if we fall behind)
     *   LSC  — link status change (cable unplug/reconnect)
     *
     * Even in poll mode, keeping these armed lets the IDT handler log
     * events and detect link changes.
     * Source: SDM §13.53; §14.7 "Receive Initialization" step 8.
     * ----------------------------------------------------------------- */
     
    // Clear any pending interrupts by reading ICR
    (void)nic_read(E1000_ICR);  /* clear any stale interrupt causes */
    // IMS (Interrupt Mask Set) - Offset 0xD0
    // 1 << 7 (RXT0) (Receiver Timer Interrupt) - Interrupt the CPU whenever a packet arrives
    // 1 << 2 (LSC) (Link Status Change) - Interrupt the CPU if the cable is unplugged
    //e1000_write_reg(mmio_base, 0x00D8, 0xFFFFFFFF); // Mask all interrupts
    nic_write(E1000_IMS, E1000_IMS_RXT0 | E1000_IMS_RXO | E1000_IMS_LSC);

    serial_print("[E1000] Initialised");
    if (mac_out) {
        serial_print("  MAC=");
        for (int i = 0; i < 6; i++) {
            serial_print_hex(mac_out[i]);
            if (i < 5) serial_print(":");
        }
    }
    serial_print("\n");

    return 0;
}

/* =========================================================================
 * e1000_send_raw
 *
 * Transmits one Ethernet frame (header + payload; no FCS — the NIC appends
 * it automatically).  Uses the next available TX descriptor in a round-robin
 * ring.
 *
 * Descriptor fields:
 *   addr   — physical address of the frame data buffer
 *   length — total frame length in bytes (must be ≥ 14 for Ethernet II)
 *   cmd    — EOP (last descriptor for this packet) | RS (request DD write-back)
 *   status — cleared to 0 before submit; NIC sets DD=1 on completion
 *
 * RS (Report Status, bit 3) is mandatory: without it the NIC never sets DD
 * and the completion poll below spins forever.
 * Source: SDM §3.3.3 Table 3-1 "Legacy Transmit Descriptor".
 *
 * The mmio_base parameter is accepted for API compatibility with the public
 * header but ignored — the driver uses the internal e1000_mmio_base_phys.
 *
 * Returns 0 on success, -1 on timeout (NIC stopped responding).
 * ========================================================================= */
SECURE_DRIVER_CODE int e1000_send_raw(uint64_t mmio_base, void *data, uint16_t len) {
    (void)mmio_base;  /* ignored; driver uses e1000_mmio_base_phys */

    // capture the index we are using for this packet
    int current_idx = tx_tail;

    // map data
    tx_ring[current_idx].addr   = (uint64_t)(uintptr_t)data;
    tx_ring[current_idx].length = len;
    tx_ring[current_idx].cmd    = E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS; // EOP | RS (Report Status)
    /* Clear DD so the poll below does not see a stale result from a
     * previous packet that used this same descriptor slot. */
    // clear status. If we wrap around later, this must be 0 so we don't think a previous finished packet is the current one.
    tx_ring[current_idx].status = 0;

    /* Advance the software tail index for the next call. */
    // update Tail to the next available slot
    tx_tail = (tx_tail + 1) % TX_RING_SIZE;

    /* Compiler memory barrier — all descriptor stores must reach RAM before
     * the TDT write that notifies the NIC.  On x86 the Total Store Order
     * memory model guarantees stores are visible to other agents in program
     * order, but the compiler may reorder them without this barrier.
     * Source: Intel SDM Vol. 3A §8.2.2 "Memory Ordering". */
    // memory barrier: ensure descriptors are written to RAM before notifying hardware
    __asm__ volatile("" ::: "memory");

    /* Writing TDT is the kick that causes the NIC to start DMA. */
    nic_write(E1000_TDT, (uint32_t)tx_tail); // TDT

    /* Poll for DD (Descriptor Done) with a bounded timeout.
     * An unbounded spin would freeze the kernel if the NIC wedges. */
    for (uint32_t i = 0; i < E1000_TX_TIMEOUT; i++) {
        if (tx_ring[current_idx].status & E1000_TXD_STAT_DD) {
            return 0;  /* packet transmitted */
        }
    }

    serial_print("[E1000] ERROR: TX timeout — NIC did not set DD\n");
    return -1;
}

/* =========================================================================
 * e1000_poll_receive
 *
 * Checks whether the next RX descriptor has been filled by the NIC
 * (DD bit set in the status field).  If so, copies the frame into the
 * caller's buffer, recycles the descriptor, and returns the number of
 * bytes copied.
 *
 * Ring ownership (SDM §14.7):
 *   Hardware writes to descriptors from RDH up to (but not including) RDT.
 *   Software recycles descriptors by advancing RDT past the consumed slot.
 *   After advancing RDT by 1, the hardware gains one more slot to fill.
 *
 * Returns the number of bytes received (> 0), or 0 if no packet is ready.
 * ========================================================================= */
SECURE_DRIVER_CODE int e1000_poll_receive(uint64_t mmio_base, void *buffer, uint16_t max_len) {
    (void)mmio_base;

    static int rx_idx = 0;

    /* Check DD bit — set by NIC when a frame has been DMA'd into the buffer. */
    // check if the current descriptor has the "Done" (DD) bit set
    if (!(rx_ring[rx_idx].status & E1000_RXD_STAT_DD)) {
        return 0;  /* no frame ready */
    }

    uint16_t len = rx_ring[rx_idx].length;
    if (len > max_len) {
        len = max_len;  /* truncate if caller's buffer is smaller */
    }

    /* Copy the received frame out of the NIC's DMA buffer.
     * The addr field in rx_ring[rx_idx] points to the page we allocated
     * in e1000_init; it remains valid for the lifetime of the ring. */
    // copy the packet data out
    memcpy(buffer, (const void *)(uintptr_t)rx_ring[rx_idx].addr, len);

    /* Clear the status field to mark the slot as reclaimable.
     * This MUST happen before we write RDT — the NIC re-checks DD=0 to
     * confirm the slot is ready for reuse. */     
    // reset the status for reuse
    rx_ring[rx_idx].status = 0;
    // advance our software index
    int old_idx = rx_idx;
    rx_idx = (rx_idx + 1) % RX_RING_SIZE;

    /* Compiler memory barrier — the status=0 store above must reach the
     * cache-coherency domain before the RDT write below.  On x86, store-store
     * ordering is guaranteed by TSO, but the compiler is free to move stores
     * without this barrier.  Source: Intel SDM Vol. 3A §8.2.2. */
     
    // memory barrier: ensure status is cleared in RAM before notifying hardware
    __asm__ volatile("" ::: "memory");

    /* Write old_idx to RDT to return the recycled descriptor to the NIC.
     * "The tail points to the first descriptor that is to be filled by software."
     * Setting RDT = old_idx tells the NIC "the slot at old_idx is now yours."
     * Source: SDM §13.76 "Receive Descriptor Tail". */
     // update the Receive Descriptor Tail (RDT)
    // We tell the hardware: "The slot at 'old_idx' is now free for you to use."
    // RDT points to the descriptor *beyond* the valid data, so we set it to the one we just cleaned. 
    nic_write(E1000_RDT, (uint32_t)old_idx);

    return (int)len;
}