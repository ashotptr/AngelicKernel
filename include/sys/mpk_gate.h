#ifndef MPK_GATE_H
#define MPK_GATE_H

/*
 * mpk_gate.h — Typed C wrappers for all e1000 driver entry points.
 *
 * Why this file exists:
 *   The assembly trampolines (mpk_trampoline_N) are untyped: they accept
 *   a function pointer and N uint64_t arguments.  Calling them directly
 *   requires casting every pointer and integer to uint64_t at each call
 *   site, which is fragile and error-prone.
 *
 *   This header provides one inline wrapper per e1000 entry point.  Each
 *   wrapper matches the exact C signature of the underlying function and
 *   performs the cast internally.  Call sites use the mpk_e1000_*()
 *   names and the compiler enforces the types.
 *
 * Usage:
 *   #include "sys/mpk_gate.h"
 *   ...
 *   mpk_e1000_init(mmio_base, mac);           // instead of e1000_init()
 *   mpk_e1000_send_raw(mmio, buf, len);       // instead of e1000_send_raw()
 *   mpk_e1000_poll_receive(mmio, buf, max);   // instead of e1000_poll_receive()
 *
 * Relationship to assembly:
 *   mpk_trampoline_2 / mpk_trampoline_3 are defined in src/arch/mpk.asm.
 *   They:
 *     1. Save all arguments to callee-saved registers (R13–R15).
 *     2. Execute WRPKRU(0x00000000) to unlock Key 1.
 *     3. Call the driver function with the saved arguments.
 *     4. Execute WRPKRU(0x0000000C) to re-lock Key 1.
 *     5. Return the driver's return value in RAX.
 *
 * PKRU encoding used here:
 *   0x00000000 — all keys accessible (inside driver call)
 *   0x0000000C — Key 1 AD=1, WD=1 (kernel default; driver pages inaccessible)
 *
 * Intel SDM Vol. 2B — WRPKRU
 * Intel SDM Vol. 3A §4.6.2 — Protection Keys
 */

#include <stdint.h>
#include "drivers/e1000.h"

/* Trampoline declarations — implemented in src/arch/mpk.asm */
extern int mpk_trampoline_2(void *func, uint64_t a0, uint64_t a1);
extern int mpk_trampoline_3(void *func, uint64_t a0, uint64_t a1, uint64_t a2);
extern int mpk_trampoline_4(void *func, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);

/*
 * mpk_e1000_init
 *
 * Wraps:  int e1000_init(uint64_t mmio_base, uint8_t *mac_out)
 * Args:   2  →  uses mpk_trampoline_2
 *
 * Called once from kernel.c to initialise the NIC and read the MAC.
 * The MAC buffer (mac_out) lives in normal kernel memory (Key 0); the
 * driver is temporarily granted Key 1 access by the trampoline and
 * writes the MAC through the pointer.
 */
static inline int mpk_e1000_init(uint64_t mmio_base, uint8_t *mac_out) {
    return mpk_trampoline_2((void*)e1000_init, mmio_base, (uint64_t)mac_out);
}

/*
 * mpk_e1000_send_raw
 *
 * Wraps:  int e1000_send_raw(uint64_t mmio_base, void *data, uint16_t len)
 * Args:   3  →  uses mpk_trampoline_3
 *
 * Called from lwip_glue.c:low_level_output() on every outgoing packet.
 * `data` points into tx_buffer (Key 0 memory); the driver reads from it
 * while temporarily holding Key 1 access to reach its own tx_ring.
 */
static inline int mpk_e1000_send_raw(uint64_t mmio_base, void *data, uint16_t len) {
    return mpk_trampoline_3((void*)e1000_send_raw, mmio_base, (uint64_t)data, (uint64_t)len);
}

/*
 * mpk_e1000_poll_receive
 *
 * Wraps:  int e1000_poll_receive(uint64_t mmio_base, void *buffer, uint16_t max_len)
 * Args:   3  →  uses mpk_trampoline_3
 *
 * Called from lwip_glue.c:angelic_netif_poll() on every poll iteration.
 * `buffer` points into rx_buffer (Key 0 memory); the driver writes the
 * received packet there from its own rx_ring (Key 1 memory).
 */
static inline int mpk_e1000_poll_receive(uint64_t mmio_base, void *buffer, uint16_t max_len) {
    return mpk_trampoline_3((void*)e1000_poll_receive, mmio_base, (uint64_t)buffer, (uint64_t)max_len);
}
 
static inline int mpk_e1000_send_scatter(uint64_t mmio_base,
                                          const void **addrs,
                                          const uint16_t *lens,
                                          int n_segs) {
    return mpk_trampoline_4((void*)e1000_send_scatter,
                             mmio_base,
                             (uint64_t)addrs,
                             (uint64_t)lens,
                             (uint64_t)(uint32_t)n_segs);
}
#endif /* MPK_GATE_H */