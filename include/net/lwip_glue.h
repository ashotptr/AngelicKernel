// include/net/lwip_glue.h
#ifndef LWIP_GLUE_H
#define LWIP_GLUE_H

#include <stdint.h>
#include "lwip/netif.h"

// Initialize the lwIP system and add our network interface
void init_network_stack(uint64_t mmio_base, uint8_t *mac);

// Poll the hardware and feed packets into lwIP
void angelic_netif_poll(void);

#endif