#ifndef ANGELIC_CONFIG_H
#define ANGELIC_CONFIG_H

/* ===========================================================================
 * config.h — AngelicKernel compile-time configuration
 *
 * Edit this file before building to match your network environment.
 * All other source files should #include this instead of hardcoding values.
 * =========================================================================== */

/* ---------------------------------------------------------------------------
 * Network configuration
 *
 * QEMU default (NAT usermode networking):
 *   IP      10.0.2.15
 *   Netmask 255.255.255.0
 *   Gateway 10.0.2.2
 *
 * Real hardware: set these to values valid on your LAN.
 * The benchmark script (testing/benchmarks/boot_time_measure.py) must point
 * at ANGELIC_IP when running against a physical machine.
 * --------------------------------------------------------------------------- */
#define ANGELIC_IP_0   10
#define ANGELIC_IP_1    0
#define ANGELIC_IP_2    2
#define ANGELIC_IP_3   15

#define ANGELIC_NM_0  255
#define ANGELIC_NM_1  255
#define ANGELIC_NM_2  255
#define ANGELIC_NM_3    0

#define ANGELIC_GW_0   10
#define ANGELIC_GW_1    0
#define ANGELIC_GW_2    2
#define ANGELIC_GW_3    2

/* XMPP server port — 5222 is the IANA-assigned XMPP client port */
#define ANGELIC_XMPP_PORT   5222

/* XMPP domain advertised in stream headers */
#define ANGELIC_XMPP_DOMAIN "angelic.local"

/* ---------------------------------------------------------------------------
 * NIC device IDs to scan
 *
 * The PCI scanner in pci.c will probe all IDs in this list.
 * All 8254x-family chips share the same register layout as the 82540EM, so
 * the e1000 driver works without modification on any of these.
 *
 * Add more IDs here if you have a different 8254x variant.
 * See: https://pci-ids.ucw.cz/read/PC/8086
 * --------------------------------------------------------------------------- */
#define ANGELIC_NIC_VENDOR   0x8086u   /* Intel */

#define ANGELIC_NIC_IDS { \
    0x100Eu,  /* 82540EM — what QEMU emulates                   */ \
    0x1076u,  /* 82541PI — very common on old desktops/laptops  */ \
    0x100Fu,  /* 82545EM — server boards, cheap on eBay         */ \
    0x1079u,  /* 82546GB — dual-port, cheap on eBay             */ \
    0x107Cu,  /* 82541PI (alternate PCI ID)                     */ \
    0x1010u,  /* 82546EB                                        */ \
    0x1011u,  /* 82545EM (copper)                               */ \
    0x1026u,  /* 82545GM                                        */ \
    0x0000u   /* sentinel — end of list                         */ \
}

/* ---------------------------------------------------------------------------
 * Memory
 * --------------------------------------------------------------------------- */

/* Physical memory reserved for the kernel's bump allocator (bytes).
 * Must be large enough to hold PMM bitmaps + DMA rings + lwIP pools.
 * 512 MB is the QEMU allocation; adjust down for real hardware if needed. */
#define ANGELIC_RAM_MB   512

/* ---------------------------------------------------------------------------
 * Serial console
 * --------------------------------------------------------------------------- */
#define ANGELIC_SERIAL_PORT  0x3F8u   /* COM1 */
#define ANGELIC_SERIAL_BAUD  115200u

/* ---------------------------------------------------------------------------
 * Build-time assertions — catch obviously wrong configs at compile time
 * --------------------------------------------------------------------------- */
_Static_assert(ANGELIC_XMPP_PORT > 0 && ANGELIC_XMPP_PORT < 65536,
               "ANGELIC_XMPP_PORT out of range");

#endif /* ANGELIC_CONFIG_H */
