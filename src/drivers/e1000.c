#include "drivers/e1000.h"
#include "sys/mpk_sections.h"
#include "mm/pmm.h"
#include <stdint.h>
#include <string.h>

extern void serial_print(const char *s);
extern void serial_print_hex(uint64_t n);

#define E1000_CTRL 0x0000u
#define E1000_STATUS 0x0008u
#define E1000_EECD 0x0010u
#define E1000_EERD 0x0014u

#define E1000_ICR 0x00C0u
#define E1000_ICS 0x00C8u
#define E1000_IMS 0x00D0u
#define E1000_IMC 0x00D8u

#define E1000_RCTL 0x0100u
#define E1000_RDBAL 0x2800u
#define E1000_RDBAH 0x2804u
#define E1000_RDLEN 0x2808u
#define E1000_RDH 0x2810u
#define E1000_RDT 0x2818u
#define E1000_RDTR 0x2820u

#define E1000_TCTL 0x0400u
#define E1000_TIPG 0x0410u
#define E1000_TDBAL 0x3800u
#define E1000_TDBAH 0x3804u
#define E1000_TDLEN 0x3808u
#define E1000_TDH 0x3810u
#define E1000_TDT 0x3818u

#define E1000_RAL0 0x5400u
#define E1000_RAH0 0x5404u

#define E1000_MTA 0x5200u
#define E1000_MTA_ENTRIES 128

#define E1000_CTRL_FD (1u << 0)
#define E1000_CTRL_ASDE (1u << 5)
#define E1000_CTRL_SLU (1u << 6)
#define E1000_CTRL_ILOS (1u << 7)
#define E1000_CTRL_SPEED_M (3u << 8)
#define E1000_CTRL_FRCSPD (1u << 11)
#define E1000_CTRL_FRCDPLX (1u << 12)
#define E1000_CTRL_RST (1u << 26)
#define E1000_CTRL_RFCE (1u << 27)
#define E1000_CTRL_TFCE (1u << 28)
#define E1000_CTRL_VME (1u << 30)
#define E1000_CTRL_PHY_RST (1u << 31)

#define E1000_RCTL_EN (1u << 1)
#define E1000_RCTL_SBP (1u << 2)
#define E1000_RCTL_UPE (1u << 3)
#define E1000_RCTL_MPE (1u << 4)
#define E1000_RCTL_LPE (1u << 5)
#define E1000_RCTL_LBM_NONE (0u << 6)
#define E1000_RCTL_RDMTS_HALF (0u << 8)
#define E1000_RCTL_BAM (1u << 15)

#define E1000_RCTL_BSIZE_2048 (0u << 16)
#define E1000_RCTL_BSIZE_1024 (1u << 16)
#define E1000_RCTL_BSIZE_512 (2u << 16)
#define E1000_RCTL_BSIZE_256 (3u << 16)
#define E1000_RCTL_VFE (1u << 18)
#define E1000_RCTL_BSEX (1u << 25)
#define E1000_RCTL_SECRC (1u << 26)

#define E1000_TCTL_EN (1u << 1)
#define E1000_TCTL_PSP (1u << 3)

#define E1000_TCTL_CT(n) (((uint32_t)(n) & 0xFFu) << 4)
#define E1000_TCTL_COLD(n) (((uint32_t)(n) & 0x3FFu) << 12)
#define E1000_TCTL_RTLC (1u << 24)

#define E1000_TIPG_802_3 (8u | (4u << 10) | (6u << 20))

#define E1000_IMS_TXDW (1u << 0)
#define E1000_IMS_LSC (1u << 2)
#define E1000_IMS_RXDMT0 (1u << 4)
#define E1000_IMS_RXO (1u << 6)
#define E1000_IMS_RXT0 (1u << 7)

#define E1000_TXD_CMD_EOP (1u << 0)
#define E1000_TXD_CMD_IFCS (1u << 1)
#define E1000_TXD_CMD_RS (1u << 3)

#define E1000_TXD_STAT_DD (1u << 0)

#define E1000_RXD_STAT_DD (1u << 0)
#define E1000_RXD_STAT_EOP (1u << 1)

#define E1000_TX_TIMEOUT 0x100000u

SECURE_DRIVER_DATA static uint64_t e1000_mmio_base_phys;
SECURE_DRIVER_DATA static int tx_tail = 0;

SECURE_DRIVER_DATA volatile struct e1000_rx_desc rx_ring[RX_RING_SIZE] __attribute__((aligned(16)));
SECURE_DRIVER_DATA volatile struct e1000_tx_desc tx_ring[TX_RING_SIZE] __attribute__((aligned(16)));

SECURE_DRIVER_CODE static inline void nic_write(uint32_t reg, uint32_t val) {
    *(volatile uint32_t *)(e1000_mmio_base_phys + reg) = val;
}

SECURE_DRIVER_CODE static inline uint32_t nic_read(uint32_t reg) {
    return *(volatile uint32_t *)(e1000_mmio_base_phys + reg);
}

SECURE_DRIVER_CODE int e1000_send_scatter(uint64_t mmio_base, const void **addrs, const uint16_t *lens, int n_segs) {
    (void)mmio_base;
 
    if (n_segs <= 0 || n_segs > TX_RING_SIZE / 2) {
        return -1;
    }
    
    int first_idx = tx_tail;
    (void)first_idx;

    for (int i = 0; i < n_segs; i++) {
        int slot = (tx_tail + i) % TX_RING_SIZE;

        if (!(tx_ring[slot].status & E1000_TXD_STAT_DD)) {
            for (uint32_t t = 0; t < E1000_TX_TIMEOUT; t++) {
                if (tx_ring[slot].status & E1000_TXD_STAT_DD) {
                    break;
                }
            }

            if (!(tx_ring[slot].status & E1000_TXD_STAT_DD)) {
                return -1;
            }
        }
    }

    for (int i = 0; i < n_segs; i++) {
        int slot = (tx_tail + i) % TX_RING_SIZE;
        int is_last = (i == n_segs - 1);
 
        tx_ring[slot].addr = (uint64_t)(uintptr_t)addrs[i];
        tx_ring[slot].length = lens[i];
        tx_ring[slot].cso = 0;
        tx_ring[slot].css = 0;
        tx_ring[slot].special = 0;

        tx_ring[slot].cmd = E1000_TXD_CMD_IFCS | E1000_TXD_CMD_RS | (is_last ? E1000_TXD_CMD_EOP : 0);
        tx_ring[slot].status = 0;
    }
 
    int last_idx = (tx_tail + n_segs - 1) % TX_RING_SIZE;
    tx_tail = (tx_tail + n_segs) % TX_RING_SIZE;
 
    __asm__ volatile("" ::: "memory");

    nic_write(E1000_TDT, (uint32_t)tx_tail);

    for (uint32_t t = 0; t < E1000_TX_TIMEOUT; t++) {
        if (tx_ring[last_idx].status & E1000_TXD_STAT_DD) {
            return 0;
        }
    }
 
    serial_print("[e1000] scatter tx timeout\n");

    return -1;
}

SECURE_DRIVER_CODE int e1000_init(uint64_t mmio_base, uint8_t *mac_out) {
    e1000_mmio_base_phys = mmio_base;

    nic_write(E1000_CTRL, nic_read(E1000_CTRL) | E1000_CTRL_RST);

    for (uint32_t i = 0; i < 0x20000u; i++) {
        if (!(nic_read(E1000_CTRL) & E1000_CTRL_RST)) {
            break;
        }
    }

    nic_write(E1000_CTRL, nic_read(E1000_CTRL) | E1000_CTRL_FD | E1000_CTRL_SLU | E1000_CTRL_ASDE);

    uint32_t ral = nic_read(E1000_RAL0);
    uint32_t rah = nic_read(E1000_RAH0);

    if (mac_out) {
        mac_out[0] = (uint8_t)( ral & 0xFFu);
        mac_out[1] = (uint8_t)((ral >> 8) & 0xFFu);
        mac_out[2] = (uint8_t)((ral >> 16) & 0xFFu);
        mac_out[3] = (uint8_t)((ral >> 24) & 0xFFu);
        mac_out[4] = (uint8_t)( rah & 0xFFu);
        mac_out[5] = (uint8_t)((rah >>  8) & 0xFFu);
    }
    
    for (int i = 0; i < E1000_MTA_ENTRIES; i++) {
        nic_write(E1000_MTA + (uint32_t)(i * 4), 0u);
    }

    for (int i = 0; i < RX_RING_SIZE; i++) {
        void *buf = pmm_alloc_page();

        if (!buf) {
            serial_print("[e1000] out of physical pages for rx ring\n");
            
            return -1;
        }

        rx_ring[i].addr = (uint64_t)(uintptr_t)buf;
        rx_ring[i].length = 0;
        rx_ring[i].checksum = 0;
        rx_ring[i].status = 0;
        rx_ring[i].errors = 0;
        rx_ring[i].special = 0;
    }

    uint64_t rx_phys = (uint64_t)(uintptr_t)rx_ring;

    nic_write(E1000_RDBAL, (uint32_t)(rx_phys & 0xFFFFFFFFu));
    nic_write(E1000_RDBAH, (uint32_t)(rx_phys >> 32));
    nic_write(E1000_RDLEN, (uint32_t)(RX_RING_SIZE * sizeof(struct e1000_rx_desc)));

    nic_write(E1000_RDH, 0u);
    nic_write(E1000_RDT, (uint32_t)(RX_RING_SIZE - 1));

    for (int i = 0; i < TX_RING_SIZE; i++) {
        tx_ring[i].addr = 0;
        tx_ring[i].length = 0;
        tx_ring[i].cso = 0;
        tx_ring[i].cmd = 0;
        tx_ring[i].status = E1000_TXD_STAT_DD;
        tx_ring[i].css = 0;
        tx_ring[i].special = 0;
    }

    uint64_t tx_phys = (uint64_t)(uintptr_t)tx_ring;

    nic_write(E1000_TDBAL, (uint32_t)(tx_phys & 0xFFFFFFFFu));
    nic_write(E1000_TDBAH, (uint32_t)(tx_phys >> 32));
    nic_write(E1000_TDLEN, (uint32_t)(TX_RING_SIZE * sizeof(struct e1000_tx_desc)));

    nic_write(E1000_TDH, 0u);
    nic_write(E1000_TDT, 0u);

    nic_write(E1000_TIPG, E1000_TIPG_802_3);
    
    nic_write(E1000_RCTL, E1000_RCTL_EN | E1000_RCTL_MPE | E1000_RCTL_BAM | E1000_RCTL_BSIZE_2048 | E1000_RCTL_SECRC);

    nic_write(E1000_TCTL, E1000_TCTL_EN | E1000_TCTL_PSP | E1000_TCTL_CT(0x0F) | E1000_TCTL_COLD(0x03F));

    (void)nic_read(E1000_ICR);
    
    nic_write(E1000_IMS, E1000_IMS_RXT0 | E1000_IMS_RXO | E1000_IMS_LSC);

    serial_print("[e1000] initialised");

    if (mac_out) {
        serial_print("  mac=");

        for (int i = 0; i < 6; i++) {
            serial_print_hex(mac_out[i]);

            if (i < 5) {
                serial_print(":");
            }
        }
    }

    serial_print("\n");

    return 0;
}

SECURE_DRIVER_CODE int e1000_send_raw(uint64_t mmio_base, void *data, uint16_t len) {
    (void)mmio_base;

    int current_idx = tx_tail;

    tx_ring[current_idx].addr = (uint64_t)(uintptr_t)data;
    tx_ring[current_idx].length = len;
    tx_ring[current_idx].cmd = E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS;
    tx_ring[current_idx].status = 0;

    tx_tail = (tx_tail + 1) % TX_RING_SIZE;

    __asm__ volatile("" ::: "memory");

    nic_write(E1000_TDT, (uint32_t)tx_tail);

    for (uint32_t i = 0; i < E1000_TX_TIMEOUT; i++) {
        if (tx_ring[current_idx].status & E1000_TXD_STAT_DD) {
            return 0;
        }
    }

    serial_print("[e1000] tx timeout (nic did not set dd)\n");

    return -1;
}

SECURE_DRIVER_CODE int e1000_poll_receive(uint64_t mmio_base, void *buffer, uint16_t max_len) {
    (void)mmio_base;

    static int rx_idx = 0;

    if (!(rx_ring[rx_idx].status & E1000_RXD_STAT_DD)) {
        return 0;
    }

    uint16_t len = rx_ring[rx_idx].length;

    if (len > max_len) {
        len = max_len;
    }

    memcpy(buffer, (const void *)(uintptr_t)rx_ring[rx_idx].addr, len);

    rx_ring[rx_idx].status = 0;

    int old_idx = rx_idx;
    rx_idx = (rx_idx + 1) % RX_RING_SIZE;

    __asm__ volatile("" ::: "memory");
    
    nic_write(E1000_RDT, (uint32_t)old_idx);

    return (int)len;
}