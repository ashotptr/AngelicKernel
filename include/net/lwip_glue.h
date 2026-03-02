#ifndef LWIP_GLUE_H
#define LWIP_GLUE_H

#include <stdint.h>
#include "lwip/netif.h"

void init_network_stack(uint64_t mmio_base, uint8_t *mac);

void angelic_netif_poll(void);

#endif