#include <efi.h>
#include <efilib.h>
#include "drivers/e1000.h"
#include "sys/mpk_sections.h"
#include "mm/pmm.h"

uint64_t e1000_mmio_base_phys = 0;

SECURE_DRIVER_DATA volatile struct e1000_rx_desc rx_ring[RX_RING_SIZE] __attribute__((aligned(16)));
SECURE_DRIVER_DATA volatile struct e1000_tx_desc tx_ring[TX_RING_SIZE] __attribute__((aligned(16)));

SECURE_DRIVER_CODE void e1000_write_reg(uint64_t base, uint32_t offset, uint32_t val) {
    *(volatile uint32_t *)(base + offset) = val;
}

SECURE_DRIVER_CODE uint32_t e1000_read_reg(uint64_t base, uint32_t offset) {
    return *(volatile uint32_t *)(base + offset);
}

SECURE_DRIVER_CODE int e1000_init(uint64_t mmio_base, uint8_t *mac_out) {
    e1000_mmio_base_phys = mmio_base;
    
    // In .secure_driver_data, we must zero them manually, because the NIC will read garbage descriptors and overwrite random memory (like your Kernel Code!) via DMA.
    for (int i = 0; i < RX_RING_SIZE; i++) {
        void* buffer = pmm_alloc_page(); 
        
        if (!buffer) {
            return -1;
        }

        rx_ring[i].addr = (uint64_t)buffer;
        rx_ring[i].status = 0;
        rx_ring[i].errors = 0;
        rx_ring[i].length = 0;
        rx_ring[i].checksum = 0;
        rx_ring[i].special = 0;
    }

    for (int i = 0; i < TX_RING_SIZE; i++) {
        tx_ring[i].addr = 0; 
        tx_ring[i].cmd = 0;
        tx_ring[i].status = 1;
        tx_ring[i].css = 0;
        tx_ring[i].special = 0;
    }

    e1000_write_reg(mmio_base, 0x0000, e1000_read_reg(mmio_base, 0x0000) | 0x40);

    uint32_t ral = e1000_read_reg(mmio_base, 0x5400); // E1000_RAL, RAL (Receive Address Low)
    uint32_t rah = e1000_read_reg(mmio_base, 0x5404); // E1000_RAH, RAH (Receive Address High).
    
    if (mac_out) {
        mac_out[0] = ral & 0xFF;
        mac_out[1] = (ral >> 8) & 0xFF;
        mac_out[2] = (ral >> 16) & 0xFF;
        mac_out[3] = (ral >> 24) & 0xFF;
        mac_out[4] = rah & 0xFF;
        mac_out[5] = (rah >> 8) & 0xFF;
    }

    uint64_t rx_addr = (uint64_t)rx_ring;
    uint64_t tx_addr = (uint64_t)tx_ring;

    e1000_write_reg(mmio_base, 0x2800, rx_addr & 0xFFFFFFFF); // RDBAL (Receive Descriptor Base Address Low)
    e1000_write_reg(mmio_base, 0x2804, rx_addr >> 32); // RDBAH (Receive Descriptor Base Address High)
    e1000_write_reg(mmio_base, 0x2808, RX_RING_SIZE * 16); // RDLEN (Receive Descriptor Length)
    
    // CRITICAL: Initialize Head and Tail
    e1000_write_reg(mmio_base, 0x2810, 0); // RDH (Head)
    e1000_write_reg(mmio_base, 0x2818, RX_RING_SIZE - 1); // RDT (Tail) - Start at end so all descriptors are available
    
    e1000_write_reg(mmio_base, 0x3800, tx_addr & 0xFFFFFFFF); // TDBAL
    e1000_write_reg(mmio_base, 0x3804, tx_addr >> 32); // TDBAH
    e1000_write_reg(mmio_base, 0x3808, TX_RING_SIZE * 16); // TDLEN
    
    // CRITICAL: Initialize Head and Tail
    e1000_write_reg(mmio_base, 0x3810, 0); // TDH (Head)
    e1000_write_reg(mmio_base, 0x3818, 0); // TDT (Tail)

    // Set RCTL: EN | SBP | UPE | MPE | LBM_NONE | RDMTS_HALF | BAM | SECRC | BSIZE_2048
    // 1 << 1 (EN): Enable Receiver. Turns the radio on.
    // 1 << 4 (MPE): Multicast Promiscuous Enabled. Accepts multicast packets.
    // 1 << 15 (BAM): Broadcast Accept Mode. Accepts broadcast packets.
    // 1 << 26 (SECRC): Strip Ethernet CRC. The hardware removes the last 4 bytes (checksum) so there is no need to process them in software.
    e1000_write_reg(mmio_base, 0x0100, (1 << 1) | (1 << 4) | (1 << 15) | (1 << 26)); 
    
    // Set TCTL: EN | PSP | CT=15 | COLD=64
    e1000_write_reg(mmio_base, 0x0400, (1 << 1) | (1 << 3) | (0x0F << 4) | (0x40 << 12));

    // IMS (Interrupt Mask Set) - Offset 0xD0
    // 1 << 7 (RXT0) (Receiver Timer Interrupt) - Interrupt the CPU whenever a packet arrives
    // 1 << 2 (LSC) (Link Status Change) - Interrupt the CPU if the cable is unplugged
    //e1000_write_reg(mmio_base, 0x00D8, 0xFFFFFFFF); // Mask all interrupts
    e1000_write_reg(mmio_base, 0x00D0, (1 << 7) | (1 << 2));

    // Clear any pending interrupts by reading ICR
    e1000_read_reg(mmio_base, 0x00C0);

    return 0; 
}

SECURE_DRIVER_CODE int e1000_send_raw(uint64_t mmio_base, void *data, uint16_t len) {
    static int tx_idx = 0;
    // capture the index we are using for this packet
    int current_idx = tx_idx;

    // map data
    tx_ring[current_idx].addr = (uint64_t)data;
    tx_ring[current_idx].length = len;
    tx_ring[current_idx].cmd = (1 << 0) | (1 << 3); // EOP | RS (Report Status)
    
    // clear status. If we wrap around later, this must be 0 so we don't think a previous finished packet is the current one.
    tx_ring[current_idx].status = 0;

    // update Tail to the next available slot
    tx_idx = (tx_idx + 1) % TX_RING_SIZE;
    
    // memory barrier: ensure descriptors are written to RAM before notifying hardware
    __asm__ volatile("" ::: "memory");
    
    e1000_write_reg(mmio_base, 0x3818, tx_idx); // TDT

    // wait for the current packet to finish
    // we now check 'current_idx', not 'tx_idx'
    while (!(tx_ring[current_idx].status & 1)); 
    
    return 0;
}

SECURE_DRIVER_CODE int e1000_poll_receive(uint64_t mmio_base, void *buffer, uint16_t max_len) {
    static int rx_idx = 0;

    // check if the current descriptor has the "Done" (DD) bit set
    if (rx_ring[rx_idx].status & 1) { 
        uint16_t len = rx_ring[rx_idx].length;
        if (len > max_len) len = max_len;
        
        // copy the packet data out
        char* packet_src = (char*)rx_ring[rx_idx].addr;
        char* packet_dst = (char*)buffer;
        
        for (uint16_t i = 0; i < len; i++) {
             packet_dst[i] = packet_src[i];
        }

        // reset the status for reuse
        rx_ring[rx_idx].status = 0;

        // advance our software index
        int old_idx = rx_idx;
        rx_idx = (rx_idx + 1) % RX_RING_SIZE;
        
        // memory barrier: ensure status is cleared in RAM before notifying hardware
        //__asm__ volatile("" ::: "memory");

        // update the Receive Descriptor Tail (RDT)
        // We tell the hardware: "The slot at 'old_idx' is now free for you to use."
        // RDT points to the descriptor *beyond* the valid data, so we set it to the one we just cleaned.
        e1000_write_reg(mmio_base, 0x2818, old_idx); 

        return len;
    }
    
    return 0; // No data
}