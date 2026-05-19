#ifndef MPK_GATE_H
#define MPK_GATE_H

#include <stdint.h>
#include "drivers/e1000.h"

extern int mpk_trampoline_2(void *func, uint64_t a0, uint64_t a1);
extern int mpk_trampoline_3(void *func, uint64_t a0, uint64_t a1, uint64_t a2);
extern int mpk_trampoline_4(void *func, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);

static inline int mpk_e1000_init(uint64_t mmio_base, uint8_t *mac_out) {
    return mpk_trampoline_2((void*)e1000_init, mmio_base, (uint64_t)mac_out);
}

static inline int mpk_e1000_send_raw(uint64_t mmio_base, void *data, uint16_t len) {
    return mpk_trampoline_3((void*)e1000_send_raw, mmio_base, (uint64_t)data, (uint64_t)len);
}

static inline int mpk_e1000_poll_receive(uint64_t mmio_base, void *buffer, uint16_t max_len) {
    return mpk_trampoline_3((void*)e1000_poll_receive, mmio_base, (uint64_t)buffer, (uint64_t)max_len);
}
 
static inline int mpk_e1000_send_scatter(uint64_t mmio_base, const void **addrs, const uint16_t *lens, int n_segs) {
    return mpk_trampoline_4((void*)e1000_send_scatter, mmio_base, (uint64_t)addrs, (uint64_t)lens, (uint64_t)(uint32_t)n_segs);
}

#endif