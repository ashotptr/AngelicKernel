#include "net/lwip_glue.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/err.h"
#include "netif/ethernet.h"
#include "drivers/e1000.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void serial_print(const char* str);

// this function must be defined for lwIP
uint32_t sys_now(void) {
    uint32_t a, d;
    // Read Time-Stamp Counter
    __asm__ volatile("rdtsc" : "=a" (a), "=d" (d));
    
    // 2GHz = 2,000,000 cycles per millisecond
    return a / 2000000; 
}

int mpk_trampoline_3(void* func, uint64_t arg1, uint64_t arg2, uint64_t arg3);
static struct netif angelic_netif;
static uint64_t global_mmio_base;

static char rx_buffer[1514];
/* BUG FIX #1: was `static char tx_buffer[1514];#define MAX_TX_SEGS 8` — the
 * #define was concatenated onto the same source line as the variable
 * declaration, which is a syntax error in C.  Split onto separate lines. */
static char tx_buffer[1514];
#define MAX_TX_SEGS  8      /* maximum pbuf chain depth we support zero-copy */

/* Fallback contiguous buffer (only used when chain is too deep) */
static char tx_buffer_fallback[1514];

/*
 * low_level_output_zerocopy — zero-copy version
 *
 * This function is called by lwIP's ethernet_input path for each outbound
 * Ethernet frame.  The pbuf chain `p` contains one fragment per element.
 *
 * Normal XMPP stanzas produce at most 2 pbuf fragments:
 *   1. Ethernet + IP + TCP header (from lwIP)
 *   2. Application payload (one pbuf per segment)
 *
 * We build a scatter array of (addr, len) pairs directly from the pbuf
 * chain and pass it to e1000_send_scatter() via the MPK trampoline.
 * No data is copied.
 *
 * BUG FIX #2: the original file had:
 *   extern err_t low_level_output_zerocopy(struct netif *netif, struct pbuf *p);
 * declared before this definition. That extern is invalid because this
 * function is `static` — a static function cannot have external linkage.
 * The extern declaration has been removed.
 */
static err_t low_level_output_zerocopy(struct netif *netif, struct pbuf *p) {
    (void)netif;
    extern uint64_t global_mmio_base;
    extern int mpk_e1000_send_scatter(uint64_t, const void**, const uint16_t*, int);

    /* Count segments */
    int n_segs = 0;
    for (struct pbuf *q = p; q != NULL; q = q->next) n_segs++;

    if (n_segs == 0) return ERR_OK;

    /* ── Fast path: scatter-gather (zero copy) ─────────────────────────── */
    if (n_segs <= MAX_TX_SEGS) {
        const void   *addrs[MAX_TX_SEGS];
        uint16_t      lens [MAX_TX_SEGS];
        int i = 0;

        for (struct pbuf *q = p; q != NULL; q = q->next) {
            addrs[i] = q->payload;
            lens [i] = (uint16_t)q->len;
            i++;
        }

#ifdef USE_MPK
        mpk_e1000_send_scatter(global_mmio_base, addrs, lens, n_segs);
#else
        /* Direct call (no MPK) — used when testing without MPK */
        extern int e1000_send_scatter(uint64_t, const void**, const uint16_t*, int);
        e1000_send_scatter(global_mmio_base, addrs, lens, n_segs);
#endif
        return ERR_OK;
    }

    /* ── Fallback: flatten into contiguous buffer ───────────────────────
     * Reached only if the pbuf chain is unusually deep.  This is the
     * original memcpy path, kept as a safety fallback.
     */
    int len = 0;
    for (struct pbuf *q = p; q != NULL; q = q->next) {
        if (len + (int)q->len > 1514) break;
        memcpy(tx_buffer_fallback + len, q->payload, q->len);
        len += q->len;
    }

#ifdef USE_MPK
    extern int mpk_trampoline_3(void*, uint64_t, uint64_t, uint64_t);
    extern int e1000_send_raw(uint64_t, void*, uint16_t);
    mpk_trampoline_3((void*)e1000_send_raw,
                     global_mmio_base,
                     (uint64_t)tx_buffer_fallback,
                     (uint64_t)len);
#else
    extern int e1000_send_raw(uint64_t, void*, uint16_t);
    e1000_send_raw(global_mmio_base, tx_buffer_fallback, len);
#endif

    return ERR_OK;
}

static err_t low_level_output(struct netif *netif, struct pbuf *p) {
    return low_level_output_zerocopy(netif, p);
}

err_t angelic_netif_init(struct netif *netif) {
    netif->name[0] = 'e';
    netif->name[1] = '0';
    netif->output = etharp_output;
    netif->linkoutput = low_level_output;
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;

    return ERR_OK;
}

void angelic_netif_poll() {
    int len;

    #ifdef USE_MPK
        len = mpk_trampoline_3((void*)e1000_poll_receive, global_mmio_base, (uint64_t)rx_buffer, 1514);
    #else
        len = e1000_poll_receive(global_mmio_base, (uint8_t*)rx_buffer, 1514);
    #endif

    if (len > 0) {
        struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
        if (p) {
            memcpy(p->payload, rx_buffer, len);
            
            if (angelic_netif.input(p, &angelic_netif) != ERR_OK) {
                pbuf_free(p);
            }
        }
    }
}

void init_network_stack(uint64_t mmio_base, uint8_t *mac) {
    global_mmio_base = mmio_base;
    
    ip4_addr_t ip, netmask, gw;
    
    IP4_ADDR(&ip, 10, 0, 2, 15);
    IP4_ADDR(&netmask, 255, 255, 255, 0);
    IP4_ADDR(&gw, 10, 0, 2, 2);
    
    serial_print("[DEBUG] Calling lwip_init()...\n");
    lwip_init();
    serial_print("[DEBUG] lwip_init() done.\n");

    //tcpip_init(tcpip_init_done, tcpip_init_done_param); 
    
    angelic_netif.hwaddr_len = 6;
    for(int i = 0; i < 6; i++) {
        angelic_netif.hwaddr[i] = mac[i];
    }

    serial_print("[DEBUG] Adding netif...\n");
    netif_add(&angelic_netif, &ip, &netmask, &gw, NULL, angelic_netif_init, ethernet_input);
    
    serial_print("[DEBUG] Setting default...\n");
    netif_set_default(&angelic_netif);
    
    serial_print("[DEBUG] Bringing interface up...\n");
    netif_set_up(&angelic_netif);

    // for(int i = 0; i < 6; i++) {
    //     angelic_netif.hwaddr[i] = mac[i];
    // }

    // angelic_netif.hwaddr_len = 6;
    
    serial_print("[DEBUG] Network Stack Initialized.\n");
}

// https://lwip.fandom.com/wiki/Writing_a_device_driver
// https://lwip.fandom.com/wiki/Guide:_integrating_baremetal_lwip_2.2_on_a_Cortex_M
// https://lwip.fandom.com/wiki/LwIP_Wiki

// 4.1.2 Example of TCP echo server demonstration