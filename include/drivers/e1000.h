#ifndef E1000_H
#define E1000_H

#include <stdint.h>

#define RX_RING_SIZE 32
#define TX_RING_SIZE 32

struct e1000_rx_desc {
    volatile uint64_t addr;
    volatile uint16_t length;
    volatile uint16_t checksum;
    volatile uint8_t status;
    volatile uint8_t errors;
    volatile uint16_t special;
} __attribute__((packed));

struct e1000_tx_desc {
    volatile uint64_t addr;
    volatile uint16_t length;
    volatile uint8_t cso;
    volatile uint8_t cmd;
    volatile uint8_t status;
    volatile uint8_t css;
    volatile uint16_t special;
} __attribute__((packed));

int e1000_init(uint64_t mmio_base, uint8_t *mac_out);
int e1000_send_raw(uint64_t mmio_base, void *data, uint16_t len);
int e1000_poll_receive(uint64_t mmio_base, void *buffer, uint16_t max_len);

#endif