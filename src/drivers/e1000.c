// src/drivers/e1000.c
#include <efi.h>
#include <efilib.h>
#include "drivers/e1000.h"
#include "sys/mpk_sections.h"

// Define the rings in Secure Data section (for MPK later)
SECURE_DRIVER_DATA volatile struct e1000_rx_desc rx_ring[RX_RING_SIZE] __attribute__((aligned(16)));
SECURE_DRIVER_DATA volatile struct e1000_tx_desc tx_ring[TX_RING_SIZE] __attribute__((aligned(16)));

// Helper to interact with MMIO
SECURE_DRIVER_CODE void e1000_write_reg(uint64_t base, uint32_t offset, uint32_t val) {
    *(volatile uint32_t *)(base + offset) = val;
}

SECURE_DRIVER_CODE uint32_t e1000_read_reg(uint64_t base, uint32_t offset) {
    return *(volatile uint32_t *)(base + offset);
}

// Initialize the card (simplified for brevity, keeps your original logic logic)
SECURE_DRIVER_CODE int e1000_init(uint64_t mmio_base, uint8_t *mac_out) {
    // 1. Detect MAC Address from EEPROM or RAL
    uint32_t ral = e1000_read_reg(mmio_base, 0x5400); // E1000_RAL
    uint32_t rah = e1000_read_reg(mmio_base, 0x5404); // E1000_RAH
    
    if (mac_out) {
        mac_out[0] = ral & 0xFF;
        mac_out[1] = (ral >> 8) & 0xFF;
        mac_out[2] = (ral >> 16) & 0xFF;
        mac_out[3] = (ral >> 24) & 0xFF;
        mac_out[4] = rah & 0xFF;
        mac_out[5] = (rah >> 8) & 0xFF;
    }

    // 2. Initialize RX/TX Rings (Link addresses to hardware)
    e1000_write_reg(mmio_base, 0x2800, (uint64_t)rx_ring & 0xFFFFFFFF); // RDBAL
    e1000_write_reg(mmio_base, 0x2804, (uint64_t)rx_ring >> 32);         // RDBAH
    e1000_write_reg(mmio_base, 0x2808, RX_RING_SIZE * 16);               // RDLEN
    
    e1000_write_reg(mmio_base, 0x3800, (uint64_t)tx_ring & 0xFFFFFFFF); // TDBAL
    e1000_write_reg(mmio_base, 0x3804, (uint64_t)tx_ring >> 32);         // TDBAH
    e1000_write_reg(mmio_base, 0x3808, TX_RING_SIZE * 16);               // TDLEN

    // 3. Enable RX (RCTL) and TX (TCTL)
    // Set RCTL: EN | SBP | UPE | MPE | LBM_NONE | RDMTS_HALF | BAM | SECRC | BSIZE_2048
    e1000_write_reg(mmio_base, 0x0100, (1 << 1) | (1 << 4) | (1 << 15) | (1 << 26)); 
    
    // Set TCTL: EN | PSP | CT=15 | COLD=64
    e1000_write_reg(mmio_base, 0x0400, (1 << 1) | (1 << 3) | (0x0F << 4) | (0x40 << 12));
// 4. Enable Interrupts
    // IMS (Interrupt Mask Set) - Offset 0xD0
    // Bit 7: RXT0 (Receiver Timer Interrupt) - Fires when a packet is received
    // Bit 2: LSC  (Link Status Change)
    e1000_write_reg(mmio_base, 0x00D0, (1 << 7) | (1 << 2));

    // Clear any pending interrupts by reading ICR
    e1000_read_reg(mmio_base, 0x00C0);
    return 0; // Success
}

SECURE_DRIVER_CODE int e1000_send_raw(uint64_t mmio_base, void *data, uint16_t len) {
    static int tx_idx = 0;
    
    // 1. Capture the index we are using for THIS packet
    int current_idx = tx_idx;

    // 2. Map data
    tx_ring[current_idx].addr = (uint64_t)data;
    tx_ring[current_idx].length = len;
    tx_ring[current_idx].cmd = (1 << 0) | (1 << 3); // EOP | RS (Report Status)
    
    // CRITICAL: Clear status. If we wrap around later, this must be 0 
    // so we don't think a previous finished packet is the current one.
    tx_ring[current_idx].status = 0;

    // 3. Update Tail to the NEXT available slot
    tx_idx = (tx_idx + 1) % TX_RING_SIZE;
    e1000_write_reg(mmio_base, 0x3818, tx_idx); // TDT

    // 4. Wait for the CURRENT packet to finish
    // FIX: We now check 'current_idx', not 'tx_idx'
    while (!(tx_ring[current_idx].status & 1)); 
    
    return 0;
}

SECURE_DRIVER_CODE int e1000_poll_receive(uint64_t mmio_base, void *buffer, uint16_t max_len) {
    static int rx_idx = 0;
    if (rx_ring[rx_idx].status & 1) { // DD (Descriptor Done) bit set
        uint16_t len = rx_ring[rx_idx].length;
        if (len > max_len) len = max_len;
        
        // Copy out (crucial for MPK isolation: copy from "Driver Page" to "App Buffer")
        CopyMem(buffer, (void*)rx_ring[rx_idx].addr, len);
        
        // Reset descriptor
        rx_ring[rx_idx].status = 0;
        
        // Advance and notify hardware
        rx_idx = (rx_idx + 1) % RX_RING_SIZE;
        e1000_write_reg(mmio_base, 0x2818, rx_idx); // RDT
        
        return len;
    }
    return 0; // No data
}